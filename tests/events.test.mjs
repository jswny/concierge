import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { createTestHarness } from "wrangler";
import { Webhook } from "standardwebhooks";
import { getExpectedTwilioSignature } from "twilio/lib/webhooks/webhooks.js";

const ACCOUNT = `AC${"a".repeat(32)}`;
const WEBHOOK_KEY_ID = `webhooks_sharedkey_${"a".repeat(26)}`;
const WEBHOOK_KEY_SECRET = "fixture-twilio-webhook-secret";
const SIGNING_SETTINGS = `key=${WEBHOOK_KEY_ID},algorithm=HMAC_SHA1`;
const TO = "+12025550101";
const FROM = "+12025550102";
const WEBHOOK = "https://concierge.j1.io/webhooks/twilio/messages";
const secret = () => `whsec_${randomBytes(32).toString("base64")}`;
const message = (overrides = {}) => ({ AccountSid: ACCOUNT, MessageSid: `SM${randomBytes(16).toString("hex")}`, From: FROM, To: TO, Body: "A private incoming fixture message", NumMedia: "0", ...overrides });
const params = (url, signingKey = secret(), args = { To: TO }) => ({ name: "twilio.message.received", arguments: args, delivery: { mode: "webhook", url, secret: signingKey } });
const harness = createTestHarness({
	root: fileURLToPath(new URL("..", import.meta.url)),
	workers: [{
		configPath: "./wrangler.jsonc",
		bindingOverrides: { BROWSER: "browser-mock" },
		vars: { CONCIERGE_DEBUG: "true" },
		secrets: { TWILIO_ACCOUNT_SID: ACCOUNT, TWILIO_WEBHOOK_KEY_ID: WEBHOOK_KEY_ID, TWILIO_WEBHOOK_KEY_SECRET: WEBHOOK_KEY_SECRET, COOKIE_ENCRYPTION_KEY: "fixture-cookie-key" },
	}, {
		config: { name: "browser-mock", main: "./tests/fixtures/browser-worker.mjs", compatibility_date: "2026-07-15" },
	}, {
		config: {
			name: "event-fixture", main: "./tests/fixtures/events-worker.mjs", compatibility_date: "2026-07-15", compatibility_flags: ["nodejs_compat", "global_fetch_strictly_public"],
			durable_objects: { bindings: [{ name: "EVENTS", class_name: "EventFixture" }] },
			migrations: [{ tag: "v1", new_sqlite_classes: ["EventFixture"] }],
		},
	}],
});
before(async () => { await harness.listen(); });
after(async () => { await harness.close(); });

async function rpc(method, args = {}, path = "/debug/mcp", server = harness) {
	const response = await server.getWorker("concierge").fetch(`https://concierge.j1.io${path}`, {
		method: "POST",
		headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": method },
		body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params: { ...args, _meta: {
			"io.modelcontextprotocol/protocolVersion": "2026-07-28",
			"io.modelcontextprotocol/clientInfo": { name: "events-test", version: "1" },
			"io.modelcontextprotocol/clientCapabilities": {},
		} } }),
	});
	if (response.status === 401) return { status: 401 };
	const body = await response.text();
	return response.headers.get("Content-Type")?.includes("text/event-stream")
		? JSON.parse(body.split("\n").find((line) => line.startsWith("data:")).slice(5)) : JSON.parse(body);
}
async function incoming(fields, overrides = {}) {
	return harness.getWorker("concierge").fetch(WEBHOOK, {
		method: "POST", body: new URLSearchParams(fields),
		headers: { "Content-Type": "application/x-www-form-urlencoded", "X-Twilio-Signature": getExpectedTwilioSignature(WEBHOOK_KEY_SECRET, WEBHOOK, fields), "X-Twilio-Webhooks-Signature-Settings": SIGNING_SETTINGS, ...overrides },
	});
}
async function fixture(instance, input) {
	const response = await harness.getWorker("event-fixture").fetch("https://fixture.test", { method: "POST", body: JSON.stringify({ instance, ...input }) });
	return response.json();
}
async function eventually(check) {
	const deadline = Date.now() + 12_000;
	while (!check()) {
		assert.ok(Date.now() < deadline, "Timed out waiting for event delivery");
		await new Promise((resolve) => setTimeout(resolve, 25));
	}
}

test("MCP Events discovers native filters separately from tools and stays OAuth-protected", async () => {
	const discovery = await rpc("server/discover");
	assert.deepEqual(discovery.result.capabilities.events, { listChanged: false });
	const listed = await rpc("events/list");
	assert.equal(listed.result.events[0].name, "twilio.message.received");
	assert.deepEqual(listed.result.events[0].delivery, ["webhook"]);
	assert.deepEqual(listed.result.events[0].inputSchema.required, ["To"]);
	assert.match(listed.result.events[0].description, /untrusted data/);
	assert.deepEqual((await rpc("tools/list")).result.tools.map(({ name }) => name), ["code"]);
	for (const method of ["events/list", "events/subscribe", "events/unsubscribe"]) assert.equal((await rpc(method, {}, "/mcp")).status, 401);
	assert.equal((await rpc("events/list", { cursor: "unknown" })).error.code, -32602);
	assert.equal((await rpc("events/poll")).error.code, -32601);
});

test("Twilio ingress verifies signatures over all parameters and rejects unsafe requests", async () => {
	const fields = message({ FutureTwilioParameter: "signed too" });
	assert.equal((await incoming(fields, { "X-Twilio-Signature": "invalid" })).status, 403);
	const tampered = await harness.getWorker("concierge").fetch(WEBHOOK, {
		method: "POST", body: new URLSearchParams({ ...fields, Body: "tampered" }),
		headers: { "Content-Type": "application/x-www-form-urlencoded", "X-Twilio-Signature": getExpectedTwilioSignature(WEBHOOK_KEY_SECRET, WEBHOOK, fields), "X-Twilio-Webhooks-Signature-Settings": SIGNING_SETTINGS },
	});
	assert.equal(tampered.status, 403);
	assert.equal((await incoming(message({ AccountSid: `AC${"c".repeat(32)}` }))).status, 403);
	assert.equal((await incoming(message(), { "X-Twilio-Webhooks-Signature-Settings": "key=unexpected,algorithm=HMAC_SHA256" })).status, 403);
	for (const settings of [
		"", `key=${WEBHOOK_KEY_ID}`, "algorithm=HMAC_SHA1",
		`key=webhooks_sharedkey_${"b".repeat(26)},algorithm=HMAC_SHA1`,
		`key=${WEBHOOK_KEY_ID},algorithm=HMAC_SHA256`,
		`key=${WEBHOOK_KEY_ID},algorithm=HMAC_SHA1,algorithm=HMAC_SHA256`,
		`key=${WEBHOOK_KEY_ID},key=${WEBHOOK_KEY_ID},algorithm=HMAC_SHA1`,
		`${SIGNING_SETTINGS},extra=unsupported`,
	]) {
		assert.equal((await incoming(message(), { "X-Twilio-Webhooks-Signature-Settings": settings })).status, 403, settings);
	}
	assert.equal((await incoming(fields, { "X-Twilio-Signature": getExpectedTwilioSignature("account-auth-token-not-the-shared-key", WEBHOOK, fields) })).status, 403);
	const legacy = await harness.getWorker("concierge").fetch(WEBHOOK, {
		method: "POST", body: new URLSearchParams(fields),
		headers: { "Content-Type": "application/x-www-form-urlencoded", "X-Twilio-Signature": getExpectedTwilioSignature(WEBHOOK_KEY_SECRET, WEBHOOK, fields) },
	});
	assert.equal(legacy.status, 403, "A valid SHA1 signature without SharedKey settings must not fall back to legacy authentication");
	assert.equal((await incoming(message({ To: "not-a-number" }))).status, 400);
	assert.equal((await incoming(message({ Body: "x".repeat(70_000) }))).status, 413);
	assert.equal((await harness.getWorker("concierge").fetch(WEBHOOK)).status, 405);
	assert.equal((await harness.getWorker("concierge").fetch(WEBHOOK, { method: "POST", body: "{}", headers: { "Content-Type": "application/json" } })).status, 415);
	const accepted = await incoming(fields);
	assert.equal(accepted.status, 200);
	assert.equal(await accepted.text(), "<Response/>");
});

test("missing or malformed SharedKey configuration disables Events and rejects ingress", async () => {
	for (const signing of [
		{ TWILIO_WEBHOOK_KEY_ID: "", TWILIO_WEBHOOK_KEY_SECRET: WEBHOOK_KEY_SECRET },
		{ TWILIO_WEBHOOK_KEY_ID: WEBHOOK_KEY_ID, TWILIO_WEBHOOK_KEY_SECRET: "" },
		{ TWILIO_WEBHOOK_KEY_ID: "SKnot-a-webhook-key", TWILIO_WEBHOOK_KEY_SECRET: WEBHOOK_KEY_SECRET },
	]) {
		const server = createTestHarness({ root: fileURLToPath(new URL("..", import.meta.url)), workers: [{
			configPath: "./wrangler.jsonc", bindingOverrides: { BROWSER: "browser-mock" }, vars: { CONCIERGE_DEBUG: "true" },
			secrets: { COOKIE_ENCRYPTION_KEY: "test-cookie-key", TWILIO_ACCOUNT_SID: ACCOUNT, ...signing },
		}, { config: { name: "browser-mock", main: "./tests/fixtures/browser-worker.mjs", compatibility_date: "2026-07-15" } }] });
		try {
			await server.listen();
			assert.equal((await rpc("server/discover", {}, "/debug/mcp", server)).result.capabilities.events, undefined);
			const fields = message();
			const response = await server.getWorker("concierge").fetch(WEBHOOK, {
				method: "POST", body: new URLSearchParams(fields),
				headers: { "Content-Type": "application/x-www-form-urlencoded", "X-Twilio-Signature": getExpectedTwilioSignature(WEBHOOK_KEY_SECRET, WEBHOOK, fields), "X-Twilio-Webhooks-Signature-Settings": SIGNING_SETTINGS },
			});
			assert.equal(response.status, 503);
			assert.equal(await response.text(), "");
		} finally { await server.close(); }
	}
});

test("one signing key and endpoint support independent subscriptions for multiple Twilio numbers", async () => {
	const original = globalThis.fetch;
	const deliveries = [];
	const subscriptions = [
		params("https://receiver.example.com/number-one", secret(), { To: TO }),
		params("https://receiver.example.com/number-two", secret(), { To: "+12025550103" }),
	];
	globalThis.fetch = async (input, init) => {
		const request = new Request(input, init);
		const subscription = subscriptions.find((item) => item.delivery.url === request.url);
		assert.ok(subscription);
		const body = await request.text();
		const event = new Webhook(subscription.delivery.secret).verify(body, Object.fromEntries(request.headers));
		if (event.type === "verification") return Response.json({ challenge: event.challenge });
		deliveries.push({ url: request.url, To: event.data.To });
		return new Response(null, { status: 204 });
	};
	try {
		for (const subscription of subscriptions) assert.equal((await rpc("events/subscribe", subscription)).error, undefined);
		for (const subscription of subscriptions) assert.equal((await incoming(message({ To: subscription.arguments.To }))).status, 200);
		await eventually(() => deliveries.length === 2);
		assert.deepEqual(deliveries.sort((a, b) => a.url.localeCompare(b.url)), subscriptions.map((item) => ({ url: item.delivery.url, To: item.arguments.To })));
	} finally {
		for (const subscription of subscriptions) {
			const { secret: _, ...delivery } = subscription.delivery;
			await rpc("events/unsubscribe", { ...subscription, delivery });
		}
		globalThis.fetch = original;
	}
});

test("rejects unknown events, invalid filters, secrets, non-public callbacks and failed challenges", async () => {
	const original = globalThis.fetch;
	let requests = 0;
	globalThis.fetch = async () => { requests++; return Response.json({ challenge: "wrong" }); };
	try {
		for (const url of ["http://receiver.example.com", "https://localhost", "https://127.0.0.1", "https://[::1]", "https://a.local", "https://receiver.example.com:444", "https://user:pass@receiver.example.com", "https://receiver.example.com/#fragment"]) {
			assert.equal((await rpc("events/subscribe", params(url))).error.code, -32602, url);
		}
		assert.equal((await rpc("events/subscribe", { ...params("https://receiver.example.com/invalid"), name: "unknown" })).error.code, -32011);
		assert.equal((await rpc("events/subscribe", params("https://receiver.example.com/invalid", "bad-secret"))).error.code, -32602);
		assert.equal((await rpc("events/subscribe", params("https://receiver.example.com/invalid", secret(), { To: TO, apiKey: "not-allowed" }))).error.code, -32602);
		assert.equal(requests, 0);
		assert.equal((await rpc("events/subscribe", params("https://receiver.example.com/invalid"))).error.code, -32015);
		assert.equal(requests, 1);
	} finally { globalThis.fetch = original; }
});

test("delivers a real MCP subscription from signed Twilio ingress, filters and deduplicates it", async () => {
	const original = globalThis.fetch;
	const key = secret();
	const subscription = params("https://receiver.example.com/lifecycle", key, { To: TO, From: FROM });
	const deliveries = [];
	let challenges = 0;
	let callbackFailure;
	globalThis.fetch = async (input, init) => {
		try {
			const request = new Request(input, init);
			assert.equal(request.url, subscription.delivery.url);
			assert.equal(request.headers.has("Authorization"), false);
			const body = await request.text();
			const event = new Webhook(key).verify(body, Object.fromEntries(request.headers));
			if (event.type === "verification") { challenges++; return Response.json({ challenge: event.challenge }); }
			deliveries.push({ body, event, subscription: request.headers.get("X-MCP-Subscription-Id") });
			return new Response(null, { status: 204 });
		} catch (error) { callbackFailure = error; throw error; }
	};
	try {
		const created = await rpc("events/subscribe", subscription);
		if (callbackFailure) throw callbackFailure;
		assert.equal(created.error, undefined);
		assert.equal(created.result.cursor, null);
		assert.equal(created.result.truncated, false);
		const refreshed = await rpc("events/subscribe", { ...subscription, arguments: { From: FROM, To: TO }, ttlMs: 120_000 });
		assert.equal(refreshed.result.id, created.result.id);
		assert.equal(challenges, 2);
		const fields = message({ FutureTwilioParameter: "preserved for signature verification" });
		assert.equal((await incoming(fields)).status, 200);
		assert.equal((await incoming(fields)).status, 200);
		await eventually(() => callbackFailure || deliveries.length === 1);
		if (callbackFailure) throw callbackFailure;
		assert.equal(deliveries[0].subscription, created.result.id);
		assert.equal(deliveries[0].event.name, "twilio.message.received");
		assert.deepEqual(deliveries[0].event.data, Object.fromEntries(Object.entries(fields).filter(([key]) => key !== "FutureTwilioParameter")));
		assert.equal(deliveries[0].event.cursor, null);
		assert.doesNotMatch(deliveries[0].body, new RegExp(`${WEBHOOK_KEY_ID}|${WEBHOOK_KEY_SECRET}|whsec_|test-api`));
		assert.equal((await incoming(message({ From: "+12025550103" }))).status, 200);
		const { secret: _, ...delivery } = subscription.delivery;
		for (let i = 0; i < 2; i++) {
			const result = await rpc("events/unsubscribe", { ...subscription, delivery });
			assert.equal(result.error, undefined);
			assert.deepEqual(Object.keys(result.result).filter((key) => !["_meta", "resultType"].includes(key)), []);
		}
		assert.equal((await incoming(message())).status, 200);
		assert.equal(deliveries.length, 1);
	} finally { globalThis.fetch = original; }
});

test("callback redirects are rejected without sending a verification to another destination", async () => {
	const original = globalThis.fetch;
	const visited = [];
	globalThis.fetch = async (input) => {
		visited.push(new Request(input).url);
		return new Response(null, { status: 302, headers: { Location: "https://another.example.com/stolen" } });
	};
	try {
		const result = await rpc("events/subscribe", params("https://receiver.example.com/redirect"));
		assert.equal(result.error.code, -32015);
		assert.deepEqual(visited, ["https://receiver.example.com/redirect"]);
	} finally { globalThis.fetch = original; }
});

test("subscription filters, idempotent removal and finite lifetimes persist independently of a service instance", async () => {
	const original = globalThis.fetch;
	globalThis.fetch = async (input, init) => Response.json({ challenge: JSON.parse(await new Request(input, init).text()).challenge });
	try {
		const subscription = params("https://receiver.example.com/filter", secret(), { To: TO, From: FROM });
		const start = Date.now();
		const created = await fixture("filter", { action: "subscribe", params: { ...subscription, ttlMs: null } });
		assert.ok(Date.parse(created.refreshBefore) <= start + 3600_000);
		await fixture("filter", { action: "publish", message: message({ From: "+12025550103" }) });
		await fixture("filter", { action: "publish", message: message({ To: "+12025550103" }) });
		assert.equal((await fixture("filter", { action: "state" })).jobs.length, 0);
		await fixture("filter", { action: "publish", message: message() });
		assert.equal((await fixture("filter", { action: "state" })).jobs.length, 1);
		const { secret: _, ...delivery } = subscription.delivery;
		await fixture("filter", { action: "unsubscribe", params: { ...subscription, delivery } });
		assert.equal((await fixture("filter", { action: "state" })).jobs.length, 0);
		const expired = await fixture("filter", { action: "subscribe", owner: { expiresAt: Date.now() - 1 }, params: subscription });
		assert.equal(expired.code, -32012);
	} finally { globalThis.fetch = original; }
});

test("persistent delivery state handles retries, secret rotation, expiry, ownership and revocation", async () => {
	const original = globalThis.fetch;
	const key = secret();
	const rotated = secret();
	const subscription = params("https://receiver.example.com/state", key);
	const attempts = [];
	let status = 503;
	globalThis.fetch = async (input, init) => {
		const request = new Request(input, init);
		const body = await request.text();
		const parsed = JSON.parse(body);
		if (parsed.type === "verification") return Response.json({ challenge: parsed.challenge });
		attempts.push({ body, headers: Object.fromEntries(request.headers) });
		return new Response(null, { status });
	};
	try {
		const created = await fixture("state", { action: "subscribe", params: subscription });
		assert.ok(created.id);
		const fields = message();
		await fixture("state", { action: "publish", message: fields });
		const stored = await fixture("state", { action: "state" });
		assert.equal(stored.jobs.length, 1);
		assert.doesNotMatch(JSON.stringify(stored.subscriptions), /whsec_/);
		assert.equal((await fixture("state", { action: "deliver" })).jobs[0].attempts, 1);
		assert.equal(attempts.length, 1);
		const otherOwner = { clientId: "another-client", grantId: "another-grant" };
		const { secret: _, ...delivery } = subscription.delivery;
		await fixture("state", { action: "unsubscribe", owner: otherOwner, params: { ...subscription, delivery } });
		assert.equal((await fixture("state", { action: "state" })).subscriptions.length, 1);
		const refreshed = await fixture("state", { action: "subscribe", params: { ...subscription, delivery: { ...subscription.delivery, secret: rotated } } });
		assert.equal(refreshed.id, created.id);
		status = 204;
		assert.equal((await fixture("state", { action: "deliver" })).jobs.length, 0);
		assert.equal(attempts.length, 2);
		assert.equal(attempts[0].body, attempts[1].body);
		new Webhook(key).verify(attempts[0].body, attempts[0].headers);
		new Webhook(key).verify(attempts[1].body, attempts[1].headers);
		new Webhook(rotated).verify(attempts[1].body, attempts[1].headers);
		await fixture("state", { action: "publish", message: fields });
		assert.equal((await fixture("state", { action: "state" })).jobs.length, 0);
		await fixture("state", { action: "publish", message: message() });
		await fixture("state", { action: "expire" });
		assert.equal((await fixture("state", { action: "deliver" })).jobs.length, 0);
		assert.equal(attempts.length, 2);
		await fixture("revocation", { action: "subscribe", params: subscription });
		await fixture("revocation", { action: "publish", message: message() });
		await fixture("revocation", { action: "revoke" });
		const revoked = await fixture("revocation", { action: "deliver" });
		assert.equal(revoked.subscriptions.length, 0);
		assert.equal(revoked.jobs.length, 0);
		assert.equal(attempts.length, 2);
		for (const terminalStatus of [410, 413]) {
			status = terminalStatus;
			await fixture(`terminal-${status}`, { action: "subscribe", params: subscription });
			await fixture(`terminal-${status}`, { action: "publish", message: message() });
			const result = await fixture(`terminal-${status}`, { action: "deliver" });
			assert.equal(result.jobs.length, 0);
			assert.equal(result.subscriptions.length, 1);
		}
	} finally { globalThis.fetch = original; }
});

test("bounds subscriptions and delivery attempts while honoring retry cooldowns", async () => {
	const original = globalThis.fetch;
	let attempts = 0;
	globalThis.fetch = async (input, init) => {
		const event = JSON.parse(await new Request(input, init).text());
		if (event.type === "verification") return Response.json({ challenge: event.challenge });
		attempts++;
		return new Response(null, { status: 429, headers: { "Retry-After": "60" } });
	};
	try {
		for (let i = 0; i < 32; i++) {
			const created = await fixture("limits", { action: "subscribe", params: params(`https://receiver.example.com/limit-${i}`) });
			assert.ok(created.id);
		}
		assert.equal((await fixture("limits", { action: "subscribe", params: params("https://receiver.example.com/limit-33") })).code, -32603);
		await fixture("bounded-retry", { action: "subscribe", params: params("https://receiver.example.com/bounded-retry") });
		await fixture("bounded-retry", { action: "publish", message: message() });
		const now = Date.now();
		const first = await fixture("bounded-retry", { action: "deliver" });
		assert.ok(first.jobs[0].next_attempt >= now + 60_000);
		for (let i = 0; i < 5; i++) await fixture("bounded-retry", { action: "deliver" });
		assert.equal(attempts, 6);
		assert.equal((await fixture("bounded-retry", { action: "state" })).jobs.length, 0);
	} finally { globalThis.fetch = original; }
});
