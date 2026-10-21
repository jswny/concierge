import { ProtocolError, type McpServer } from "@modelcontextprotocol/server";
import { Webhook } from "standardwebhooks";
import { timingSafeEqual } from "node:crypto";
import { z } from "zod";

export interface EventSource {
	definition: { name: string; description: string; delivery: string[]; inputSchema: Record<string, unknown>; payloadSchema: Record<string, unknown> };
	parseArguments(value: unknown): Record<string, unknown>;
	matches(args: Record<string, unknown>, data: Record<string, unknown>): boolean;
}

export const callbackUrl = z.string().max(2048).transform((value, ctx) => {
	try {
		const url = new URL(value);
		if (url.protocol !== "https:" || url.username || url.password || url.hash || (url.port && url.port !== "443") ||
			!url.hostname.includes(".") || url.hostname.endsWith(".") || /^[\d.]+$/.test(url.hostname) ||
			url.hostname.includes(":") || /\.(localhost|local|internal|test|invalid|example)$/i.test(url.hostname)) throw new Error();
		return url.href;
	} catch {
		ctx.addIssue({ code: "custom", message: "A public HTTPS callback on port 443 is required." });
		return z.NEVER;
	}
});
const signingSecret = z.string().max(128).refine((value) => {
	if (!/^whsec_[A-Za-z0-9+/]+={0,2}$/.test(value)) return false;
	const bytes = Buffer.from(value.slice(6), "base64");
	return bytes.length >= 24 && bytes.length <= 64 && bytes.toString("base64").replace(/=+$/, "") === value.slice(6).replace(/=+$/, "");
}, "A whsec_ signing secret containing 24–64 base64-encoded bytes is required.");
const identity = {
	name: z.string().min(1).max(128),
	arguments: z.record(z.string(), z.unknown()),
};
export const subscribeParams = z.strictObject({
	...identity,
	delivery: z.strictObject({ mode: z.literal("webhook"), url: callbackUrl, secret: signingSecret }),
	ttlMs: z.number().int().positive().nullable().optional(),
	cursor: z.string().max(2048).nullable().optional(),
	maxAgeMs: z.number().nonnegative().nullable().optional(),
	_meta: z.record(z.string(), z.unknown()).optional(),
});
export const unsubscribeParams = z.strictObject({
	...identity,
	delivery: z.strictObject({ mode: z.literal("webhook").optional(), url: callbackUrl }),
	_meta: z.record(z.string(), z.unknown()).optional(),
});
export type SubscribeParams = z.infer<typeof subscribeParams>;
export type UnsubscribeParams = z.infer<typeof unsubscribeParams>;

export interface EventOwner {
	userId: string;
	clientId: string;
	grantId: string;
	expiresAt: number;
}

export interface EventMethods {
	subscribe(params: SubscribeParams, owner: EventOwner): Promise<Record<string, unknown>>;
	unsubscribe(params: UnsubscribeParams, owner: EventOwner): Promise<Record<string, unknown>>;
}

export function registerEventMethods(server: McpServer, sources: readonly EventSource[], service: EventMethods, owner: () => Promise<EventOwner>) {
	async function operation(run: () => Promise<Record<string, unknown>>) {
		try { return await run(); }
		catch (error) {
			if (error instanceof ProtocolError) throw error;
			throw new ProtocolError(-32603, "Event subscription operation failed.");
		}
	}
	const capabilities = { ...server.server.getCapabilities(), events: { listChanged: false } };
	server.server.registerCapabilities(capabilities);
	server.server.setRequestHandler("events/list", {
		params: z.strictObject({ cursor: z.string().optional(), _meta: z.record(z.string(), z.unknown()).optional() }),
	}, async ({ cursor }) => {
		await owner();
		if (cursor) throw new ProtocolError(-32602, "This event catalog has no continuation cursor.");
		return { events: sources.map((source) => source.definition) };
	});
	server.server.setRequestHandler("events/subscribe", { params: subscribeParams }, (params) => operation(async () => service.subscribe(params, await owner())));
	server.server.setRequestHandler("events/unsubscribe", { params: unsubscribeParams }, (params) => operation(async () => service.unsubscribe(params, await owner())));
}

// Public-only Workers fetch blocks private destinations at connection time. Never
// use a service/private-network binding or follow redirects for client callbacks.
export function publicCallbackFetch(url: string, init: RequestInit): Promise<Response> {
	return fetch(callbackUrl.parse(url), { ...init, redirect: "manual" });
}

export function webhookHeaders(id: string, subscriptionId: string, body: string, secret: string, previousSecret?: string) {
	const signedAt = new Date();
	const signature = new Webhook(secret).sign(id, signedAt, body);
	return {
		"Content-Type": "application/json",
		"webhook-id": id,
		"webhook-timestamp": String(Math.floor(signedAt.getTime() / 1000)),
		"webhook-signature": previousSecret ? `${signature} ${new Webhook(previousSecret).sign(id, signedAt, body)}` : signature,
		"X-MCP-Subscription-Id": subscriptionId,
	};
}

export async function readBoundedBody(request: Request | Response, limit: number): Promise<Uint8Array> {
	const reader = request.body?.getReader();
	if (!reader) return new Uint8Array();
	const chunks: Uint8Array[] = [];
	let length = 0;
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			length += value.byteLength;
			if (length > limit) throw new Error("Event body exceeds limit.");
			chunks.push(value);
		}
	} finally {
		await reader.cancel().catch(() => undefined);
		reader.releaseLock();
	}
	const result = new Uint8Array(length);
	let offset = 0;
	for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.length; }
	return result;
}

export async function verifyCallback(id: string, url: string, secret: string): Promise<void> {
	const challenge = crypto.randomUUID();
	const body = JSON.stringify({ type: "verification", challenge });
	try {
		const response = await publicCallbackFetch(url, {
			method: "POST", body,
			headers: webhookHeaders(`msg_verification_${crypto.randomUUID()}`, id, body, secret),
			signal: AbortSignal.timeout(10_000),
		});
		if (!response.ok) {
			await response.body?.cancel();
			throw new Error();
		}
		const result: unknown = JSON.parse(new TextDecoder().decode(await readBoundedBody(response, 4096)));
		const returned = typeof result === "object" && result !== null && "challenge" in result ? result.challenge : undefined;
		if (typeof returned !== "string") throw new Error();
		const received = Buffer.from(returned);
		const expected = Buffer.from(challenge);
		if (received.length !== expected.length || !timingSafeEqual(received, expected)) throw new Error();
	} catch {
		throw new ProtocolError(-32015, "CallbackEndpointError", { reason: "challenge_failed" });
	}
}
