import { ProtocolError } from "@modelcontextprotocol/server";
import { CompactEncrypt, compactDecrypt } from "jose";
import { parseRetryAfter } from "../connector-requests";
import {
	verifyCallback, webhookHeaders, publicCallbackFetch,
	type EventOwner, type EventSource, type SubscribeParams, type UnsubscribeParams,
} from "./protocol";

const DEFAULT_TTL = 30 * 60_000;
const MAX_TTL = 60 * 60_000;
const RECEIPT_TTL = 24 * 60 * 60_000;
const RETRY_DELAYS = [1000, 5000, 30_000, 120_000, 600_000];
const MAX_SUBSCRIPTIONS = 32;
const MAX_PENDING = 1024;

type Subscription = {
	id: string;
	name: string;
	owner: string;
	url: string;
	arguments: string;
	secret: string;
	expires: number;
};
type Delivery = { id: string; subscription: string; body: string; attempts: number };
type SecretState = { id: string; current: string; previous?: string; previousUntil?: number };

export class McpEvents {
	private readonly sql: SqlStorage;
	private readonly mutations = new Map<string, Promise<unknown>>();
	private readonly key: Promise<Uint8Array>;

	constructor(
		private readonly ctx: DurableObjectState,
		encryptionSecret: string,
		private readonly sources: readonly EventSource[],
		private readonly isAuthorized: (owner: EventOwner) => Promise<boolean>,
	) {
		this.sql = ctx.storage.sql;
		this.key = crypto.subtle.digest("SHA-256", new TextEncoder().encode(`concierge:mcp-events:v1:${encryptionSecret}`)).then((value) => new Uint8Array(value));
		this.sql.exec(`CREATE TABLE IF NOT EXISTS mcp_event_subscriptions (
			id TEXT PRIMARY KEY, name TEXT NOT NULL, owner TEXT NOT NULL, url TEXT NOT NULL,
			arguments TEXT NOT NULL, secret TEXT NOT NULL, expires INTEGER NOT NULL
		)`);
		this.sql.exec(`CREATE TABLE IF NOT EXISTS mcp_event_deliveries (
			id TEXT NOT NULL, subscription TEXT NOT NULL, body TEXT NOT NULL,
			attempts INTEGER NOT NULL DEFAULT 0, next_attempt INTEGER NOT NULL,
			PRIMARY KEY (id, subscription)
		)`);
		this.sql.exec("CREATE INDEX IF NOT EXISTS mcp_event_due ON mcp_event_deliveries(next_attempt)");
		this.sql.exec("CREATE TABLE IF NOT EXISTS mcp_event_receipts (id TEXT PRIMARY KEY, expires INTEGER NOT NULL)");
	}

	private async serialize<T>(id: string, action: () => Promise<T>): Promise<T> {
		const pending = (this.mutations.get(id) ?? Promise.resolve()).catch(() => undefined).then(action);
		this.mutations.set(id, pending);
		try { return await pending; }
		finally { if (this.mutations.get(id) === pending) this.mutations.delete(id); }
	}

	private async identity(params: SubscribeParams | UnsubscribeParams, owner: EventOwner) {
		const source = this.sources.find((source) => source.definition.name === params.name);
		if (!source) throw new ProtocolError(-32011, "NotFound", { kind: "event" });
		let filters: Record<string, unknown>;
		try { filters = source.parseArguments(params.arguments); }
		catch { throw new ProtocolError(-32602, "Invalid event filters."); }
		const args = canonicalJson(filters);
		const principal = JSON.stringify({ userId: owner.userId, clientId: owner.clientId, grantId: owner.grantId });
		const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify([principal, params.delivery.url, params.name, args])));
		return { id: `sub_${Buffer.from(digest).toString("hex")}`, args, principal };
	}

	async subscribe(params: SubscribeParams, owner: EventOwner) {
		const { id, args, principal } = await this.identity(params, owner);
		return this.serialize(id, async () => {
			this.cleanup();
			const now = Date.now();
			const expires = Math.min(now + Math.max(60_000, Math.min(params.ttlMs ?? MAX_TTL, MAX_TTL)), owner.expiresAt - 1000);
			const grantedExpiry = params.ttlMs === undefined ? Math.min(expires, now + DEFAULT_TTL) : expires;
			if (grantedExpiry <= now) throw new ProtocolError(-32012, "Refresh authentication before subscribing.");
			const previous = this.subscription(id);
			if (!previous && this.count("mcp_event_subscriptions") >= MAX_SUBSCRIPTIONS) throw new ProtocolError(-32603, "Event subscription limit reached.");
			await verifyCallback(id, params.delivery.url, params.delivery.secret);
			if (grantedExpiry <= Date.now() || !await this.isAuthorized(owner)) throw new ProtocolError(-32012, "Event authorization expired or was revoked.");
			const previousSecret = previous ? await this.openSecret(previous) : undefined;
			const secret: SecretState = { id, current: params.delivery.secret };
			if (previousSecret && previousSecret.current !== secret.current) {
				secret.previous = previousSecret.current;
				secret.previousUntil = now + 5 * 60_000;
			} else if (previousSecret?.previousUntil && previousSecret.previousUntil > now) {
				secret.previous = previousSecret.previous;
				secret.previousUntil = previousSecret.previousUntil;
			}
			const sealed = await new CompactEncrypt(new TextEncoder().encode(JSON.stringify(secret)))
				.setProtectedHeader({ alg: "dir", enc: "A256GCM" }).encrypt(await this.key);
			// Ensure cleanup remains scheduled even after an isolate restart.
			await this.wakeBy(grantedExpiry);
			if (!this.subscription(id) && this.count("mcp_event_subscriptions") >= MAX_SUBSCRIPTIONS) throw new ProtocolError(-32603, "Event subscription limit reached.");
			this.sql.exec(`INSERT INTO mcp_event_subscriptions (id, name, owner, url, arguments, secret, expires)
				VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET secret=excluded.secret, expires=excluded.expires`,
				id, params.name, principal, params.delivery.url, args, sealed, grantedExpiry);
			return { id, refreshBefore: new Date(grantedExpiry).toISOString(), cursor: null, truncated: false };
		});
	}

	async unsubscribe(params: UnsubscribeParams, owner: EventOwner) {
		const { id } = await this.identity(params, owner);
		return this.serialize(id, async () => {
			this.removeSubscription(id);
			await this.scheduleNext();
			return {};
		});
	}

	async publish(name: string, sourceId: string, data: Record<string, unknown>): Promise<void> {
		this.cleanup();
		const source = this.sources.find((source) => source.definition.name === name);
		if (!source) throw new Error("Unknown event source.");
		const id = `${name}:${sourceId}`;
		if (this.sql.exec("SELECT id FROM mcp_event_receipts WHERE id = ?", id).toArray().length) return;
		const subscriptions = this.sql.exec<Subscription>("SELECT * FROM mcp_event_subscriptions WHERE name = ? AND expires > ?", name, Date.now()).toArray()
			.filter((subscription) => source.matches(JSON.parse(subscription.arguments), data));
		if (!subscriptions.length) return;
		if (this.count("mcp_event_deliveries") + subscriptions.length > MAX_PENDING || this.count("mcp_event_receipts") >= 10_000) {
			throw new Error("Event ingress capacity exceeded.");
		}
		const now = Date.now();
		const body = JSON.stringify({ eventId: id, name, timestamp: new Date(now).toISOString(), data, cursor: null });
		if (Buffer.byteLength(body) > 256 * 1024) throw new Error("Event payload exceeds limit.");
		// Schedule before committing: a failure cannot leave acknowledged work
		// unscheduled. SQL writes below are synchronous and atomically deduplicate.
		await this.wakeBy(now + 1000);
		this.ctx.storage.transactionSync(() => {
			if (this.sql.exec("SELECT id FROM mcp_event_receipts WHERE id = ?", id).toArray().length) return;
			if (this.count("mcp_event_deliveries") + subscriptions.length > MAX_PENDING || this.count("mcp_event_receipts") >= 10_000) throw new Error("Event ingress capacity exceeded.");
			this.sql.exec("INSERT INTO mcp_event_receipts (id, expires) VALUES (?, ?)", id, now + RECEIPT_TTL);
			for (const subscription of subscriptions) {
				// An unsubscribe/expiry during alarm scheduling must not resurrect work.
				const current = this.subscription(subscription.id);
				if (current && current.expires > Date.now()) {
					this.sql.exec("INSERT INTO mcp_event_deliveries (id, subscription, body, next_attempt) VALUES (?, ?, ?, ?)", id, subscription.id, body, now);
				}
			}
		});
	}

	async alarm(): Promise<void> {
		this.cleanup();
		const due = this.sql.exec<Delivery>("SELECT * FROM mcp_event_deliveries WHERE next_attempt <= ? ORDER BY next_attempt LIMIT 16", Date.now()).toArray();
		for (const job of due) {
			const subscription = this.subscription(job.subscription);
			if (!subscription || subscription.expires <= Date.now()) { this.removeDelivery(job); continue; }
			const owner = JSON.parse(subscription.owner) as Omit<EventOwner, "expiresAt">;
			if (!await this.isAuthorized({ ...owner, expiresAt: subscription.expires })) {
				this.removeSubscription(subscription.id);
				continue;
			}
			let status = 0;
			let retryAfter = 0;
			try {
				const secret = await this.openSecret(subscription);
				const response = await publicCallbackFetch(subscription.url, {
					method: "POST", body: job.body,
					headers: webhookHeaders(job.id, subscription.id, job.body, secret.current,
						secret.previousUntil && secret.previousUntil > Date.now() ? secret.previous : undefined),
					signal: AbortSignal.timeout(10_000),
				});
				status = response.status;
				retryAfter = parseRetryAfter(response.headers.get("Retry-After")) ?? 0;
				await response.body?.cancel();
			} catch { /* Retry transport failures without retaining exception payloads. */ }
			const terminal = (status >= 200 && status < 300) || status === 410 || status === 413 || job.attempts >= RETRY_DELAYS.length;
			if (terminal) this.removeDelivery(job);
			else this.sql.exec("UPDATE mcp_event_deliveries SET attempts = attempts + 1, next_attempt = ? WHERE id = ? AND subscription = ?",
				Date.now() + Math.max(RETRY_DELAYS[job.attempts], Math.min(retryAfter, MAX_TTL)), job.id, job.subscription);
			try { console.log(JSON.stringify({ event: "mcp_event_delivery", eventName: subscription.name, status, attempt: job.attempts + 1, outcome: status >= 200 && status < 300 ? "accepted" : terminal ? "abandoned" : "retry" })); } catch {}
		}
		await this.scheduleNext();
	}

	private subscription(id: string): Subscription | undefined {
		return this.sql.exec<Subscription>("SELECT * FROM mcp_event_subscriptions WHERE id = ?", id).toArray()[0];
	}
	private count(table: "mcp_event_subscriptions" | "mcp_event_deliveries" | "mcp_event_receipts") {
		return this.sql.exec<{ total: number }>(`SELECT COUNT(*) AS total FROM ${table}`).one().total;
	}
	private async openSecret(subscription: Subscription): Promise<SecretState> {
		const { plaintext } = await compactDecrypt(subscription.secret, await this.key, { keyManagementAlgorithms: ["dir"], contentEncryptionAlgorithms: ["A256GCM"] });
		const value = JSON.parse(new TextDecoder().decode(plaintext)) as SecretState;
		if (value.id !== subscription.id) throw new Error("Subscription secret identity mismatch.");
		return value;
	}
	private removeDelivery(job: Delivery) {
		this.sql.exec("DELETE FROM mcp_event_deliveries WHERE id = ? AND subscription = ?", job.id, job.subscription);
	}
	private removeSubscription(id: string) {
		this.ctx.storage.transactionSync(() => {
			this.sql.exec("DELETE FROM mcp_event_subscriptions WHERE id = ?", id);
			this.sql.exec("DELETE FROM mcp_event_deliveries WHERE subscription = ?", id);
		});
	}
	private cleanup() {
		this.ctx.storage.transactionSync(() => {
			this.sql.exec("DELETE FROM mcp_event_subscriptions WHERE expires <= ?", Date.now());
			this.sql.exec("DELETE FROM mcp_event_deliveries WHERE subscription NOT IN (SELECT id FROM mcp_event_subscriptions)");
			this.sql.exec("DELETE FROM mcp_event_receipts WHERE expires <= ?", Date.now());
		});
	}
	private async wakeBy(time: number) {
		await this.ctx.storage.transaction(async (txn) => {
			const previous = await txn.getAlarm();
			await txn.setAlarm(Math.min(previous ?? time, time));
		});
	}
	private async scheduleNext() {
		const row = this.sql.exec<{ time: number | null }>(`SELECT MIN(time) AS time FROM (
			SELECT MIN(next_attempt) AS time FROM mcp_event_deliveries UNION ALL
			SELECT MIN(expires) AS time FROM mcp_event_subscriptions UNION ALL
			SELECT MIN(expires) AS time FROM mcp_event_receipts
		)`).one();
		if (row.time === null) await this.ctx.storage.deleteAlarm();
		else await this.ctx.storage.setAlarm(Math.max(Date.now() + 100, row.time));
	}
}

function canonicalJson(value: unknown): string {
	if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
	if (value !== null && typeof value === "object") {
		return `{${Object.entries(value).filter(([, item]) => item !== undefined).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
			.map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(",")}}`;
	}
	return JSON.stringify(value);
}
