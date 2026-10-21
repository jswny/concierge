import { validateRequest } from "twilio/lib/webhooks/webhooks.js";
import { readBoundedBody } from "../../mcp-events/protocol";
import { messagePayload, type IncomingMessage } from "./events";

export const TWILIO_WEBHOOK_PATH = "/webhooks/twilio/messages";
export const TWILIO_WEBHOOK_URL = `https://concierge.j1.io${TWILIO_WEBHOOK_PATH}`;
type SigningEnv = Pick<Env, "TWILIO_WEBHOOK_KEY_ID" | "TWILIO_WEBHOOK_KEY_SECRET">;

export function hasTwilioWebhookKey(env: SigningEnv): boolean {
	return /^webhooks_sharedkey_[A-Za-z0-9]{26}$/.test(env.TWILIO_WEBHOOK_KEY_ID ?? "") && Boolean(env.TWILIO_WEBHOOK_KEY_SECRET);
}

function matchesSigningSettings(header: string | null, keyId: string): boolean {
	if (!header) return false;
	const settings = new Map<string, string>();
	for (const part of header.split(",")) {
		const match = /^\s*(key|algorithm)\s*=\s*([^\s,=]+)\s*$/.exec(part);
		if (!match || settings.has(match[1])) return false;
		settings.set(match[1], match[2]);
	}
	return settings.size === 2 && settings.get("key") === keyId && settings.get("algorithm") === "HMAC_SHA1";
}

export async function handleTwilioWebhook(
	request: Request,
	env: SigningEnv & Pick<Env, "TWILIO_ACCOUNT_SID">,
	accept: (message: IncomingMessage) => Promise<void>,
): Promise<Response> {
	if (request.method !== "POST") return new Response(null, { status: 405, headers: { Allow: "POST" } });
	const url = new URL(request.url);
	if (url.origin !== "https://concierge.j1.io" || url.search || url.port) return new Response(null, { status: 400 });
	if (!hasTwilioWebhookKey(env)) return new Response(null, { status: 503 });
	if (request.headers.get("Content-Type")?.split(";", 1)[0].trim().toLowerCase() !== "application/x-www-form-urlencoded") {
		return new Response(null, { status: 415 });
	}
	// Pin the dedicated key and SHA1 before using Twilio's SDK validator. Never
	// fall back to account-token signatures or trust a caller-selected algorithm.
	if (!matchesSigningSettings(request.headers.get("X-Twilio-Webhooks-Signature-Settings"), env.TWILIO_WEBHOOK_KEY_ID)) {
		return new Response(null, { status: 403 });
	}
	let form: URLSearchParams;
	try { form = new URLSearchParams(new TextDecoder().decode(await readBoundedBody(request, 64 * 1024))); }
	catch { return new Response(null, { status: 413 }); }
	const fields: Record<string, string | string[]> = Object.create(null);
	for (const name of new Set(form.keys())) {
		const values = form.getAll(name);
		fields[name] = values.length === 1 ? values[0] : values;
	}
	if (!validateRequest(env.TWILIO_WEBHOOK_KEY_SECRET, request.headers.get("X-Twilio-Signature") ?? "", TWILIO_WEBHOOK_URL, fields)) {
		return new Response(null, { status: 403 });
	}
	if (form.getAll("AccountSid").length !== 1 || form.get("AccountSid") !== env.TWILIO_ACCOUNT_SID) return new Response(null, { status: 403 });
	const names = ["AccountSid", "MessageSid", "From", "To", "Body", "NumMedia"];
	if (names.some((name) => form.getAll(name).length !== 1)) return new Response(null, { status: 400 });
	const parsed = messagePayload.safeParse(Object.fromEntries(names.map((name) => [name, form.get(name)])));
	if (!parsed.success) return new Response(null, { status: 400 });
	try { await accept(parsed.data); }
	catch { return new Response(null, { status: 503 }); }
	return new Response("<Response/>", { headers: { "Content-Type": "text/xml; charset=utf-8" } });
}
