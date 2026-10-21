import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes, sign, verify } from "node:crypto";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import {
	Client,
	StreamableHTTPClientTransport,
} from "@modelcontextprotocol/client";
import { createTestHarness } from "wrangler";
import { z } from "zod";
import { JPEG_BASE64 } from "./fixtures/jpeg.mjs";

const JPEG = Buffer.from(JPEG_BASE64, "base64");

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const MODERN_PROTOCOL_VERSION = "2026-07-28";
const LEGACY_PROTOCOL_VERSION = "2025-11-25";

const MCP_ICONS = [
	{ src: "https://concierge.j1.io/assets/concierge.png", mimeType: "image/png", sizes: ["256x256"] },
	{ src: "https://concierge.j1.io/assets/concierge.svg", mimeType: "image/svg+xml", sizes: ["any"] },
];

const GOOGLE_KEYS = generateKeyPairSync("rsa", { modulusLength: 2048 });
const KALSHI_KEYS = generateKeyPairSync("ed25519");
const ACCESS_ISSUER = "https://access.example/cdn-cgi/access/sso/oidc/test-access-client";

const GOOGLE_CREDENTIALS = {
	type: "service_account",
	client_email: "concierge@j1-concierge.iam.gserviceaccount.com",
	private_key_id: "test-google-key-id",
	private_key: GOOGLE_KEYS.privateKey.export({ type: "pkcs8", format: "pem" }),
};

const TEST_SECRETS = {
	ACCESS_AUTHORIZATION_URL: `${ACCESS_ISSUER}/authorization`,
	ACCESS_CLIENT_ID: "test-access-client",
	ACCESS_CLIENT_SECRET: "test-access-secret",
	ACCESS_JWKS_URL: `${ACCESS_ISSUER}/jwks`,
	ACCESS_TOKEN_URL: `${ACCESS_ISSUER}/token`,
	COOKIE_ENCRYPTION_KEY: "0000000000000000000000000000000000000000000000000000000000000000",
	GOOGLE_SERVICE_ACCOUNT_JSON: JSON.stringify(GOOGLE_CREDENTIALS),
	GOOGLE_MAPS_API_KEY: "test-maps-api-key",
	UNIFI_API_KEY: "test-unifi-api-key",
	TWILIO_ACCOUNT_SID: `AC${"a".repeat(32)}`,
	TWILIO_API_KEY_SID: `SK${"b".repeat(32)}`,
	TWILIO_API_KEY_SECRET: "test-twilio-api-secret",
	TWILIO_WEBHOOK_KEY_ID: `webhooks_sharedkey_${"a".repeat(26)}`,
	TWILIO_WEBHOOK_KEY_SECRET: "test-twilio-webhook-secret",
	EXA_API_KEY: "test-exa-api-key",
	KALSHI_API_KEY_ID: "test-kalshi-key-id",
	KALSHI_PRIVATE_KEY: KALSHI_KEYS.privateKey.export({ type: "pkcs8", format: "pem" }),
};

const debugServer = createConciergeHarness(true);
const productionServer = createConciergeHarness(false);
let debugMcpUrl;

before(async () => {
	const debugListener = await debugServer.listen();
	debugMcpUrl = new URL("/debug/mcp", debugListener.url);
	await productionServer.listen();
});

after(async () => {
	await Promise.all([debugServer.close(), productionServer.close()]);
});

test("keeps the production MCP route behind OAuth", async () => {
	const debugResponse = await productionServer.fetch("/debug/mcp");
	assert.equal(debugResponse.status, 404);

	const mcpResponse = await productionServer.getWorker("concierge").fetch(
		"https://concierge.j1.io/mcp",
		mcpInitializeRequest(),
	);

	assert.equal(mcpResponse.status, 401);
	assert.match(mcpResponse.headers.get("WWW-Authenticate") ?? "", /resource_metadata=/);
	assert.equal(await mcpResponse.text(), "");

	const registrationResponse = await productionServer.fetch("/register", {
		method: "POST",
	});

	assert.equal(registrationResponse.status, 404);
});

test("advertises CIMD without dynamic client registration", async () => {
	const authorizationResponse = await productionServer.getWorker("concierge").fetch(
		"https://concierge.j1.io/.well-known/oauth-authorization-server",
	);

	assert.equal(authorizationResponse.status, 200);
	const authorizationMetadata = await authorizationResponse.json();
	assert.equal(authorizationMetadata.client_id_metadata_document_supported, true);
	assert.equal(Object.hasOwn(authorizationMetadata, "registration_endpoint"), false);
	assert.equal(authorizationMetadata.authorization_endpoint, "https://concierge.j1.io/authorize");
	assert.equal(authorizationMetadata.token_endpoint, "https://concierge.j1.io/token");
	assert.ok(authorizationMetadata.token_endpoint_auth_methods_supported.includes("none"));
	assert.ok(authorizationMetadata.token_endpoint_auth_methods_supported.includes("private_key_jwt"));
	assert.deepEqual(authorizationMetadata.token_endpoint_auth_signing_alg_values_supported, ["RS256", "ES256"]);

	const resourceResponse = await productionServer.getWorker("concierge").fetch(
		"https://concierge.j1.io/.well-known/oauth-protected-resource/mcp",
	);

	assert.equal(resourceResponse.status, 200);
	const resourceMetadata = await resourceResponse.json();
	assert.equal(resourceMetadata.resource, "https://concierge.j1.io/mcp");
	assert.deepEqual(resourceMetadata.bearer_methods_supported, ["header"]);
});

test("serves only the public logo assets without OAuth", async () => {
	const response = await productionServer.fetch("/assets/concierge.svg");
	assert.equal(response.status, 200);
	assert.match(response.headers.get("Content-Type"), /^image\/svg\+xml/);
	assert.equal(response.headers.has("Set-Cookie"), false);
	assert.equal(response.headers.has("WWW-Authenticate"), false);
	const svg = await response.text();
	assert.match(svg, /<title id="title">Concierge<\/title>/);
	assert.doesNotMatch(svg, /<script|https?:\/\/(?!www\.w3\.org\/2000\/svg)/);
	const pngResponse = await productionServer.fetch("/assets/concierge.png");
	assert.equal(pngResponse.status, 200);
	assert.match(pngResponse.headers.get("Content-Type"), /^image\/png/);
	assert.equal(pngResponse.headers.has("Set-Cookie"), false);
	assert.equal(pngResponse.headers.has("WWW-Authenticate"), false);
	const png = Buffer.from(await pngResponse.arrayBuffer());
	assert.deepEqual(png.subarray(0, 8), Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
	assert.equal(png.readUInt32BE(16), 256);
	assert.equal(png.readUInt32BE(20), 256);
	assert.ok(png.length <= 10_000, "PNG must fit ChatGPT's 10 kB upload limit.");

	for (const path of ["/assets/concierge.svg", "/assets/concierge.png"]) {
		const head = await productionServer.fetch(path, { method: "HEAD" });
		assert.equal(head.status, 200);
		assert.equal(await head.text(), "");
		const post = await productionServer.fetch(path, { method: "POST" });
		assert.ok([404, 405].includes(post.status));
	}

	for (const path of ["/assets/missing.svg", "/assets/", "/assets/../src/index.ts"]) {
		assert.equal((await productionServer.fetch(path)).status, 404, path);
	}
});

test("authorizes a CIMD public client through Access and refreshes its MCP token", () => testCimdAuthorization("none"));

test("authenticates a CIMD private_key_jwt client and rejects invalid or replayed assertions", () => testCimdAuthorization("private_key_jwt"));

test("allows CIMD authentication choices without downgrading invalid assertions to none", () => testCimdAuthorization("choice"));

async function testCimdAuthorization(authMethod) {
	const signedClient = authMethod !== "none";
	const clientId = `https://client.example/${authMethod}.json`;
	const redirectUri = "https://client.example/callback";
	const verifier = randomBytes(32).toString("base64url");
	const clientKeys = generateKeyPairSync("rsa", { modulusLength: 2048 });
	const tokenEndpoint = "https://concierge.j1.io/token";

	function clientAssertion(claims = {}, key = clientKeys.privateKey) {
		const now = Math.floor(Date.now() / 1000);

		const data = [{ alg: "RS256", kid: "client-key" }, {
			iss: clientId, sub: clientId, aud: tokenEndpoint,
			iat: now, exp: now + 300, jti: randomBytes(16).toString("hex"), ...claims,
		}].map((part) => Buffer.from(JSON.stringify(part)).toString("base64url")).join(".");

		return `${data}.${sign("RSA-SHA256", Buffer.from(data), key).toString("base64url")}`;
	}

	function clientAuthentication(assertion) {
		return signedClient ? {
			client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			client_assertion: assertion,
		} : { client_secret: "", client_assertion_type: "", client_assertion: "" };
	}

	const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
	const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: "test-key" })).toString("base64url");

	const claims = Buffer.from(JSON.stringify({
		aud: TEST_SECRETS.ACCESS_CLIENT_ID,
		email: "test@example.com",
		exp: Math.floor(Date.now() / 1000) + 300,
		iat: Math.floor(Date.now() / 1000),
		iss: ACCESS_ISSUER,
		name: "Test User",
		sub: "test-user",
	})).toString("base64url");

	const tokenData = `${header}.${claims}`;
	const idToken = `${tokenData}.${sign("RSA-SHA256", Buffer.from(tokenData), privateKey).toString("base64url")}`;
	const originalFetch = globalThis.fetch;
	let upstreamTokenRequest;
	globalThis.fetch = async (input, init) => {
		const request = new Request(input, init);

		if (request.url === clientId) {
			assert.match(request.headers.get("User-Agent") ?? "", /^workers-oauth-provider\//);

			const metadata = {
				client_id: clientId,
				client_name: "Test MCP Client",
				grant_types: ["authorization_code", "refresh_token"],
				redirect_uris: [redirectUri, "https://client.example/other-callback"],
				response_types: ["code"],
				token_endpoint_auth_method: authMethod === "choice" ? "none" : authMethod,
			};

			if (authMethod === "choice") metadata.token_endpoint_auth_methods_supported = ["none", "private_key_jwt"];

			if (signedClient) metadata.jwks = { keys: [{ ...clientKeys.publicKey.export({ format: "jwk" }), kid: "client-key", alg: "RS256", use: "sig" }] };

			return Response.json(metadata);
		}

		if (request.url === TEST_SECRETS.ACCESS_TOKEN_URL) {
			upstreamTokenRequest = new URLSearchParams(await request.text());

			return Response.json({ access_token: "test-upstream-token", token_type: "Bearer", id_token: idToken });
		}

		if (request.url === TEST_SECRETS.ACCESS_JWKS_URL) {
			return Response.json({ keys: [{ ...publicKey.export({ format: "jwk" }), kid: "test-key" }] });
		}

		if (new URL(request.url).hostname === "events-client.example.com") {
			return Response.json({ challenge: (await request.json()).challenge });
		}

		return originalFetch(input, init);
	};

	const worker = productionServer.getWorker("concierge");

	try {
		const authorizeUrl = new URL("https://concierge.j1.io/authorize");
		authorizeUrl.search = new URLSearchParams({
			client_id: clientId,
			code_challenge: createHash("sha256").update(verifier).digest("base64url"),
			code_challenge_method: "S256",
			redirect_uri: redirectUri,
			resource: "https://concierge.j1.io/mcp",
			response_type: "code",
			state: "test-client-state",
		}).toString();
		const consent = await worker.fetch(authorizeUrl);
		assert.equal(consent.status, 200);
		const html = await consent.text();
		const form = consentForm(html, "approve");
		assert.doesNotMatch(html, /name="(?:state|csrf_token)"/);
		assert.match(html, /Published by <strong>client.example<\/strong>/);
		assert.equal(consent.headers.get("X-Frame-Options"), "DENY");
		assert.equal(consent.headers.get("Content-Security-Policy"), "frame-ancestors 'none'");
		assert.match(consent.headers.get("Set-Cookie"), /Secure/);
		assert.match(consent.headers.get("Set-Cookie"), /HttpOnly/);
		const consentCookies = responseCookies(consent);

		for (const cookie of ["", consentCookies.replace(/=.*/, "=wrong-browser")]) {
			const unbound = await worker.fetch("https://concierge.j1.io/authorize", {
				method: "POST", redirect: "manual", headers: { Cookie: cookie }, body: form,
			});

			assert.equal(unbound.status, 400);
		}

		// Extra form fields must never override the server-stored authorization request.
		form.set("state", "forged-state");
		form.set("redirect_uri", "https://evil.example/callback");

		const approval = await worker.fetch("https://concierge.j1.io/authorize", {
			method: "POST",
			redirect: "manual",
			headers: { Cookie: consentCookies },
			body: form,
		});

		assert.equal(approval.status, 302);

		const replayedApproval = await worker.fetch("https://concierge.j1.io/authorize", {
			method: "POST", redirect: "manual", headers: { Cookie: consentCookies }, body: form,
		});

		assert.equal(replayedApproval.status, 400);
		const approvalCookies = responseCookies(approval);

		const remembered = await worker.fetch(authorizeUrl, {
			redirect: "manual", headers: { Cookie: approvalCookies },
		});

		assert.equal(remembered.status, 302);
		assert.equal(new URL(remembered.headers.get("Location")).origin, "https://access.example");

		const tamperedRemembered = await worker.fetch(authorizeUrl, {
			redirect: "manual", headers: { Cookie: approvalCookies.replace(/(__Host-oauth-approvals=)[^;]+/, "$1tampered") },
		});

		assert.equal(tamperedRemembered.status, 200);
		const changedRedirect = new URL(authorizeUrl);
		changedRedirect.searchParams.set("redirect_uri", "https://client.example/other-callback");

		const newConsent = await worker.fetch(changedRedirect, {
			redirect: "manual", headers: { Cookie: approvalCookies },
		});

		assert.equal(newConsent.status, 200);
		const changedScope = new URL(authorizeUrl);
		changedScope.searchParams.set("scope", "new-permission");
		assert.equal((await worker.fetch(changedScope, {
			redirect: "manual", headers: { Cookie: approvalCookies },
		})).status, 200);
		const upstreamUrl = new URL(approval.headers.get("Location"));
		assert.equal(upstreamUrl.origin, "https://access.example");
		const callbackUrl = new URL("https://concierge.j1.io/callback");
		callbackUrl.search = new URLSearchParams({
			code: "test-access-code",
			state: upstreamUrl.searchParams.get("state"),
		}).toString();
		const unboundCallback = await worker.fetch(callbackUrl, { redirect: "manual" });
		assert.equal(unboundCallback.status, 400);
		assert.equal(upstreamTokenRequest, undefined);

		const callback = await worker.fetch(callbackUrl, {
			redirect: "manual", headers: { Cookie: approvalCookies },
		});

		assert.equal(callback.status, 302);

		const replayedCallback = await worker.fetch(callbackUrl, {
			redirect: "manual", headers: { Cookie: approvalCookies },
		});

		assert.equal(replayedCallback.status, 400);
		assert.equal(upstreamTokenRequest.get("code"), "test-access-code");
		assert.equal(upstreamTokenRequest.get("client_id"), TEST_SECRETS.ACCESS_CLIENT_ID);
		assert.equal(upstreamTokenRequest.get("client_secret"), TEST_SECRETS.ACCESS_CLIENT_SECRET);
		assert.equal(upstreamTokenRequest.get("grant_type"), "authorization_code");
		assert.equal(upstreamTokenRequest.get("redirect_uri"), "https://concierge.j1.io/callback");
		assert.equal(
			createHash("sha256").update(upstreamTokenRequest.get("code_verifier")).digest("base64url"),
			upstreamUrl.searchParams.get("code_challenge"),
		);
		const clientCallback = new URL(callback.headers.get("Location"));
		assert.equal(clientCallback.origin, "https://client.example");
		assert.equal(clientCallback.searchParams.get("state"), "test-client-state");

		const exchangeBody = {
			client_id: clientId,
			code: clientCallback.searchParams.get("code"),
			code_verifier: verifier,
			grant_type: "authorization_code",
			redirect_uri: redirectUri,
			resource: "https://concierge.j1.io/mcp",
		};

		if (signedClient) {
			for (const assertion of [
				...(authMethod === "private_key_jwt" ? [undefined] : []),
				clientAssertion({ aud: "https://other.example/token" }),
				clientAssertion({ sub: "https://other.example/client" }),
				clientAssertion({ exp: Math.floor(Date.now() / 1000) - 120 }),
				clientAssertion({}, privateKey),
			]) {
				const rejectedBody = { ...exchangeBody };

				if (assertion) Object.assign(rejectedBody, clientAuthentication(assertion));

				const rejected = await worker.fetch(tokenEndpoint, {
					method: "POST",
					body: new URLSearchParams(rejectedBody),
				});

				assert.equal(rejected.status, 401);
				assert.equal((await rejected.json()).error, "invalid_client");
			}
		}

		const assertion = clientAssertion();

		const exchange = await worker.fetch(tokenEndpoint, {
			method: "POST",
			body: new URLSearchParams({ ...exchangeBody, ...clientAuthentication(assertion) }),
		});

		assert.equal(exchange.status, 200);
		const tokens = await exchange.json();
		assert.doesNotThrow(() => z.object({ access_token: z.string(), refresh_token: z.string() }).parse(tokens));

		if (signedClient) {
			const replay = await worker.fetch(tokenEndpoint, {
				method: "POST",
				body: new URLSearchParams({
					client_id: clientId, grant_type: "refresh_token", refresh_token: tokens.refresh_token,
					...clientAuthentication(assertion),
				}),
			});

			assert.equal(replay.status, 401);
			assert.equal((await replay.json()).error, "invalid_client");
		}

		const refresh = await worker.fetch("https://concierge.j1.io/token", {
			method: "POST",
			body: new URLSearchParams({
				client_id: clientId,
				grant_type: "refresh_token",
				refresh_token: tokens.refresh_token,
				...clientAuthentication(clientAssertion()),
			}),
		});

		assert.equal(refresh.status, 200);
		const refreshed = await refresh.json();

		const eventRequest = async (method, params = {}) => {
			const response = await worker.fetch("https://concierge.j1.io/mcp", {
				method: "POST",
				headers: { Authorization: `Bearer ${refreshed.access_token}`, "Content-Type": "application/json", Accept: "application/json, text/event-stream", "MCP-Protocol-Version": MODERN_PROTOCOL_VERSION, "Mcp-Method": method },
				body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params: { ...params, _meta: {
					"io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
					"io.modelcontextprotocol/clientInfo": { name: "authenticated-events-test", version: "1" },
					"io.modelcontextprotocol/clientCapabilities": {},
				} } }),
			});

			assert.equal(response.status, 200);

			return response.json();
		};

		assert.equal((await eventRequest("events/list")).result.events[0].name, "twilio.message.received");
		const subscription = { name: "twilio.message.received", arguments: {}, delivery: { mode: "webhook", url: `https://events-client.example.com/${authMethod}`, secret: `whsec_${randomBytes(32).toString("base64")}` } };
		const subscribed = await eventRequest("events/subscribe", subscription);
		assert.equal(subscribed.error, undefined, JSON.stringify(subscribed.error));
		assert.match(subscribed.result.id, /^sub_/);
		const { secret: _eventSecret, ...eventDelivery } = subscription.delivery;
		assert.equal((await eventRequest("events/unsubscribe", { ...subscription, delivery: eventDelivery })).error, undefined);
		const client = new Client({ name: "authenticated-test", version: "1.0.0" });

		try {
			await client.connect(new StreamableHTTPClientTransport(new URL("https://concierge.j1.io/mcp"), {
				fetch: (input, init) => worker.fetch(input, init),
				requestInit: { headers: { Authorization: `Bearer ${refreshed.access_token}` } },
			}));
			const { tools } = await client.listTools();
			assert.deepEqual(tools.map((tool) => tool.name), ["code"]);
		} finally {
			await client.close();
		}
	} finally {
		globalThis.fetch = originalFetch;
	}
}

test("validates Access OAuth responses and ID tokens before issuing MCP authorization codes", async (t) => {
	const clientId = "https://identity-client.example/metadata.json";
	const redirectUri = "https://identity-client.example/callback";
	const worker = productionServer.getWorker("concierge");
	const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
	const wrongKey = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
	const now = Math.floor(Date.now() / 1000);

	const validClaims = {
		iss: ACCESS_ISSUER, aud: TEST_SECRETS.ACCESS_CLIENT_ID,
		sub: "test-user", iat: now, exp: now + 300,
		email: "do-not-expose@example.com",
	};

	const cases = [
		{ name: "accepts a valid ID token", claims: {}, accepted: true },
		{ name: "accepts the sole trusted audience in an array with matching azp", claims: { aud: [TEST_SECRETS.ACCESS_CLIENT_ID], azp: TEST_SECRETS.ACCESS_CLIENT_ID }, accepted: true },
		{ name: "rejects the wrong issuer", claims: { iss: "https://other.example" } },
		{ name: "rejects a missing issuer", claims: { iss: undefined } },
		{ name: "rejects the wrong audience", claims: { aud: "another-access-client" } },
		{ name: "rejects a missing audience", claims: { aud: undefined } },
		{ name: "rejects untrusted additional audiences", claims: { aud: [TEST_SECRETS.ACCESS_CLIENT_ID, "another-access-client"] } },
		{ name: "rejects additional audiences even with the correct authorized party", claims: { aud: [TEST_SECRETS.ACCESS_CLIENT_ID, "another-access-client"], azp: TEST_SECRETS.ACCESS_CLIENT_ID } },
		{ name: "rejects the wrong authorized party", claims: { azp: "another-access-client" } },
		{ name: "rejects a missing expiry", claims: { exp: undefined } },
		{ name: "rejects a string expiry", claims: { exp: String(now + 300) } },
		{ name: "rejects a null expiry", claims: { exp: null } },
		{ name: "rejects an expired token", claims: { exp: now - 1 } },
		{ name: "rejects expiry at the current time", claims: { exp: now } },
		{ name: "rejects a missing issue time", claims: { iat: undefined } },
		{ name: "rejects a string issue time", claims: { iat: String(now) } },
		{ name: "rejects a missing subject", claims: { sub: undefined } },
		{ name: "rejects an empty subject", claims: { sub: "" } },
		{ name: "rejects a non-string subject", claims: { sub: 123 } },
		{ name: "rejects a future not-before time", claims: { nbf: now + 300 } },
		{ name: "rejects an invalid signature", claims: {}, key: wrongKey },
		{ name: "rejects an unknown signing key", claims: {}, header: { kid: "unknown-key" } },
		{ name: "rejects an unexpected signing algorithm", claims: {}, header: { alg: "RS384" } },
		{ name: "rejects an unsigned token", claims: {}, unsigned: true },
		{ name: "rejects a malformed token", token: "do-not-expose-token" },
		{ name: "accepts a matching callback issuer", callback: { iss: ACCESS_ISSUER }, accepted: true },
		{ name: "rejects the wrong callback issuer", callback: { iss: "https://other.example" }, noExchange: true },
		{ name: "rejects duplicate authorization codes", duplicateCode: true, noExchange: true },
		{ name: "rejects implicit ID tokens in the callback", callback: { id_token: "do-not-expose-token" }, noExchange: true },
		{ name: "rejects implicit tokens in the callback", callback: { token: "do-not-expose-token" }, noExchange: true },
		{ name: "rejects JARM responses in the callback", callback: { response: "do-not-expose-token" }, noExchange: true },
		{ name: "rejects a missing access token", tokenFields: { access_token: undefined } },
		{ name: "rejects an empty access token", tokenFields: { access_token: "" } },
		{ name: "rejects a missing ID token", tokenFields: { id_token: undefined } },
		{ name: "rejects an empty ID token", tokenFields: { id_token: "" } },
		{ name: "rejects a missing token type", tokenFields: { token_type: undefined } },
		{ name: "rejects an unsupported token type", tokenFields: { token_type: "do-not-expose-token" } },
		{ name: "rejects invalid token expiry metadata", tokenFields: { expires_in: "invalid" } },
		{ name: "rejects an unsolicited ID-token nonce", claims: { nonce: "do-not-expose-nonce" } },
		{ name: "hides upstream token endpoint errors", tokenFields: { error: "invalid_grant", error_description: "do-not-expose-error" }, tokenStatus: 400 },
		{ name: "hides upstream token endpoint failures", tokenStatus: 503 },
		{ name: "rejects malformed token response bodies", rawTokenBody: "do-not-expose-error" },
		{ name: "does not follow token endpoint redirects", tokenStatus: 302 },
		{ name: "does not follow JWKS endpoint redirects", jwksRedirect: true },
	];

	let idToken;
	let currentExample;
	let exchangeCount = 0;
	let redirectedRequests = 0;
	const originalFetch = globalThis.fetch;
	globalThis.fetch = async (input, init) => {
		const request = new Request(input, init);

		if (request.url === clientId) {
			return Response.json({ client_id: clientId, client_name: "Identity Test Client", redirect_uris: [redirectUri], response_types: ["code"], token_endpoint_auth_method: "none" });
		}

		if (request.url === TEST_SECRETS.ACCESS_TOKEN_URL) {
			exchangeCount++;

			if (currentExample.rawTokenBody) return new Response(currentExample.rawTokenBody, { headers: { "Content-Type": "application/json" } });

			if (currentExample.tokenStatus === 302) return new Response(null, { status: 302, headers: { Location: "https://untrusted.example/oauth" } });

			return Response.json({ access_token: "do-not-expose-upstream-token", token_type: "Bearer", id_token: idToken, ...currentExample.tokenFields }, { status: currentExample.tokenStatus ?? 200 });
		}

		if (request.url === TEST_SECRETS.ACCESS_JWKS_URL) {
			if (currentExample.jwksRedirect) return new Response(null, { status: 302, headers: { Location: "https://untrusted.example/jwks" } });

			return Response.json({ keys: [{ ...publicKey.export({ format: "jwk" }), kid: "identity-test-key", alg: "RS256", use: "sig" }] });
		}

		if (new URL(request.url).hostname === "untrusted.example") {
			redirectedRequests++;

			return Response.json({});
		}

		return originalFetch(input, init);
	};

	try {
		for (const example of cases) {
			await t.test(example.name, async () => {
				currentExample = example;
				const header = { alg: "RS256", kid: "identity-test-key", ...example.header };

				if (example.unsigned) header.alg = "none";

				const data = [header, { ...validClaims, ...example.claims }]
					.map((part) => Buffer.from(JSON.stringify(part)).toString("base64url")).join(".");

				const signature = example.unsigned ? "" : sign(header.alg === "RS384" ? "RSA-SHA384" : "RSA-SHA256", Buffer.from(data), example.key ?? privateKey).toString("base64url");
				idToken = example.token ?? `${data}.${signature}`;
				const authorizeUrl = new URL("https://concierge.j1.io/authorize");
				authorizeUrl.search = new URLSearchParams({
					client_id: clientId, redirect_uri: redirectUri, response_type: "code",
					resource: "https://concierge.j1.io/mcp", state: example.name,
					code_challenge: createHash("sha256").update(randomBytes(32)).digest("base64url"),
					code_challenge_method: "S256",
				}).toString();
				const consent = await worker.fetch(authorizeUrl);
				assert.equal(consent.status, 200, consent.status === 200 ? undefined : await consent.text());

				const approval = await worker.fetch("https://concierge.j1.io/authorize", {
					method: "POST", redirect: "manual", headers: { Cookie: responseCookies(consent) },
					body: consentForm(await consent.text(), "approve"),
				});

				assert.equal(approval.status, 302);
				const callbackUrl = new URL("https://concierge.j1.io/callback");
				callbackUrl.search = new URLSearchParams({ code: "test-access-code", state: new URL(approval.headers.get("Location")).searchParams.get("state"), ...example.callback }).toString();

				if (example.duplicateCode) callbackUrl.searchParams.append("code", "another-code");
				const callbackOptions = { redirect: "manual", headers: { Cookie: responseCookies(approval) } };
				const beforeExchange = exchangeCount;
				const result = await worker.fetch(callbackUrl, callbackOptions);
				assert.equal(exchangeCount - beforeExchange, example.noExchange ? 0 : 1);
				assert.equal(redirectedRequests, 0);

				if (example.accepted) {
					assert.equal(result.status, 302);
					const destination = new URL(result.headers.get("Location"));
					assert.equal(destination.origin + destination.pathname, redirectUri);
					assert.ok(destination.searchParams.get("code"));
				} else {
					assert.equal(result.status, 400);
					assert.equal(result.headers.get("Location"), null);
					assert.equal(await result.text(), "Access identity could not be verified.");
					assert.match(result.headers.get("Set-Cookie"), /Max-Age=0/);
					const count = exchangeCount;
					assert.equal((await worker.fetch(callbackUrl, callbackOptions)).status, 400);
					assert.equal(exchangeCount, count, "Rejected identity transactions must not be replayable");
				}
			});
		}
	} finally {
		globalThis.fetch = originalFetch;
	}
});

test("handles consent denial, expired transactions, and independent upstream logins", async () => {
	const clientId = "https://consent-client.example/metadata.json";
	const redirectUri = "https://consent-client.example/callback";
	const worker = productionServer.getWorker("concierge");
	const originalFetch = globalThis.fetch;
	globalThis.fetch = async (input, init) => {
		const request = new Request(input, init);

		if (request.url === clientId) {
			return Response.json({
				client_id: clientId,
				client_name: '<script>alert("client")</script>',
				redirect_uris: [redirectUri],
				response_types: ["code"],
				token_endpoint_auth_method: "none",
			});
		}

		if (request.url === TEST_SECRETS.ACCESS_TOKEN_URL) {
			assert.fail("Denied or invalid callbacks must not exchange an Access code");
		}

		return originalFetch(input, init);
	};

	async function start(state) {
		const url = new URL("https://concierge.j1.io/authorize");
		url.search = new URLSearchParams({
			client_id: clientId, redirect_uri: redirectUri,
			response_type: "code", resource: "https://concierge.j1.io/mcp", state,
			code_challenge: createHash("sha256").update(randomBytes(32)).digest("base64url"),
			code_challenge_method: "S256",
		}).toString();
		const response = await worker.fetch(url, { redirect: "manual" });
		assert.equal(response.status, 200);
		const html = await response.text();
		assert.doesNotMatch(html, /<script>/);
		assert.match(html, /&#60;script&#62;/);

		return { form: consentForm(html, "approve"), cookie: responseCookies(response) };
	}

	async function submit(consent, decision) {
		consent.form.set("decision", decision);

		return worker.fetch("https://concierge.j1.io/authorize", {
			method: "POST", redirect: "manual", headers: { Cookie: consent.cookie }, body: consent.form,
		});
	}

	try {
		const invalidRedirect = new URL("https://concierge.j1.io/authorize");
		invalidRedirect.search = new URLSearchParams({
			client_id: clientId, redirect_uri: "https://evil.example/callback", response_type: "code",
		}).toString();
		const invalid = await worker.fetch(invalidRedirect, { redirect: "manual" });
		assert.equal(invalid.status, 400);
		assert.equal(invalid.headers.get("Location"), null);
		const validRedirect = new URL(invalidRedirect);
		validRedirect.searchParams.set("redirect_uri", redirectUri);
		validRedirect.searchParams.set("state", "invalid-request-state");
		const safeError = await worker.fetch(validRedirect, { redirect: "manual" });
		assert.equal(safeError.status, 302);
		const errorDestination = new URL(safeError.headers.get("Location"));
		assert.equal(errorDestination.origin + errorDestination.pathname, redirectUri);
		assert.equal(errorDestination.searchParams.get("error"), "invalid_request");
		assert.equal(errorDestination.searchParams.get("state"), "invalid-request-state");

		const denied = await start("denied-state");
		const denial = await submit(denied, "deny");
		assert.equal(denial.status, 302);
		const destination = new URL(denial.headers.get("Location"));
		assert.equal(destination.origin + destination.pathname, redirectUri);
		assert.equal(destination.searchParams.get("error"), "access_denied");
		assert.equal(destination.searchParams.get("state"), "denied-state");
		assert.equal(destination.searchParams.get("iss"), "https://concierge.j1.io");
		assert.equal((await submit(denied, "approve")).status, 400);

		const expired = await start("expired-state");
		const key = `transaction:${createHash("sha256").update(expired.form.get("handle")).digest("hex")}`;
		const { OAUTH_KV } = await worker.getEnv();
		const { keys } = await OAUTH_KV.list({ prefix: key });
		assert.equal(keys.length, 1);
		assert.ok(keys[0].expiration > Date.now() / 1000 + 550);
		assert.ok(keys[0].expiration <= Date.now() / 1000 + 601);
		// Removing the KV entry simulates expiry without waiting ten minutes.
		await OAUTH_KV.delete(key);
		assert.equal((await submit(expired, "approve")).status, 400);

		const first = await start("first-state");
		const second = await start("second-state");
		assert.notEqual(first.cookie.split("=")[0], second.cookie.split("=")[0]);
		const approvals = [await submit(first, "approve"), await submit(second, "approve")];
		const cookies = approvals.map(responseCookies);

		for (const [index, approval] of approvals.entries()) {
			assert.equal(approval.status, 302);
			const callback = new URL("https://concierge.j1.io/callback");
			callback.searchParams.set("state", new URL(approval.headers.get("Location")).searchParams.get("state"));
			callback.searchParams.set("error", "access_denied");
			assert.equal((await worker.fetch(callback, {
				redirect: "manual", headers: { Cookie: cookies[1 - index] },
			})).status, 400);

			const result = await worker.fetch(callback, {
				redirect: "manual", headers: { Cookie: cookies.join("; ") },
			});

			assert.equal(result.status, 302);
			const clientCallback = new URL(result.headers.get("Location"));
			assert.equal(clientCallback.searchParams.get("state"), index === 0 ? "first-state" : "second-state");
			assert.equal(clientCallback.searchParams.get("error"), "access_denied");
		}
	} finally {
		globalThis.fetch = originalFetch;
	}
});

test("rejects untrusted MCP Host and Origin headers", async () => {
	const badHostResponse = await debugServer.fetch(
		"http://evil.example/debug/mcp",
		mcpInitializeRequest(),
	);

	assert.equal(badHostResponse.status, 403);
	assert.match(await badHostResponse.text(), /Invalid Host/);

	const worker = debugServer.getWorker("concierge");

	const badOriginResponse = await worker.fetch(
		"http://localhost/debug/mcp",
		mcpInitializeRequest({ Origin: "https://evil.example" }),
	);

	assert.equal(badOriginResponse.status, 403);
	assert.match(await badOriginResponse.text(), /Invalid Origin/);
});

test("bounds streamed MCP bodies by actual bytes and cancels oversized input", async () => {
	const limit = 4 * 1024 * 1024;
	const fixture = debugServer.getWorker("mcp-infrastructure-test");
	const run = async (options) => (await fixture.fetch("/", { method: "POST", body: JSON.stringify(options) })).json();

	for (const contentLength of [undefined, 1, "invalid"]) {
		const result = await run({ chunks: [limit, 1, 10], contentLength });
		assert.equal(result.status, 413);
		assert.equal(result.cancelled, true);
		assert.equal(result.chunksRead, 2);
		assert.match(result.error.error.message, /4194304 bytes/);
	}

	const announced = await run({ chunks: [1], contentLength: limit + 1 });
	assert.equal(announced.status, 413);
	assert.equal(announced.cancelled, true);
	assert.equal(announced.chunksRead, 0);

	for (const chunks of [[], [1, 2, 3], [limit]]) {
		const result = await run({ chunks });
		assert.equal(result.status, 200);
		assert.equal(result.size, chunks.reduce((a, b) => a + b, 0));
		assert.equal(result.header, "preserved");
		assert.equal(result.url, "http://localhost/debug/mcp");
		assert.equal(result.method, "POST");
		assert.equal(result.cancelled, false);
	}

	assert.equal((await run({ chunks: [1, 2], failAfterChunks: 1 })).error, "test body failure");
});

test("limits MCP ingress without bypassing OAuth or debug gating", async () => {
	const limit = 4 * 1024 * 1024;

	const run = async (options, server = debugServer) => (await server.getWorker("mcp-infrastructure-test").fetch("/", {
		method: "POST", body: JSON.stringify({ action: "ingress", count: limit, ...options }),
	})).json();

	const response = await run({});
	assert.equal(response.status, 413);
	assert.equal(response.headers["access-control-allow-origin"], "*");
	assert.doesNotMatch(response.body, /xxxxx/);
	assert.match(JSON.parse(response.body).error.message, /4194304 bytes/);
	const unicode = await run({ character: "\u00e9", count: limit / 2 });
	assert.ok(unicode.requestChars < limit);
	assert.ok(unicode.requestBytes > limit);
	assert.equal(unicode.status, 413, "The body limit counts UTF-8 bytes, not characters.");
	const message = JSON.parse(mcpInitializeRequest().body);
	const emptySize = Buffer.byteLength(JSON.stringify({ ...message, params: { ...message.params, _meta: { padding: "" } } }));
	const boundary = await run({ message, count: limit - emptySize });
	assert.equal(boundary.requestBytes, limit);
	assert.equal(boundary.status, 200, boundary.body);
	assert.match(boundary.body, new RegExp(`"protocolVersion":"${LEGACY_PROTOCOL_VERSION}"`));
	assert.equal((await run({ message, count: limit - emptySize + 1 })).status, 413);
	const production = await run({ path: "/mcp" }, productionServer);
	assert.equal(production.status, 401);
	assert.match(production.headers["www-authenticate"], /resource_metadata=/);
	assert.equal((await run({ path: "/debug/mcp" }, productionServer)).status, 404);
});

test("advertises and enforces the submitted code length limit", async () => {
	await withMcpClient(undefined, async (client) => {
		const limit = 1_000_000;
		const { tools } = await client.listTools();
		assert.equal(tools[0].inputSchema.properties.code.maxLength, limit);
		const prefix = "async () => 1 /*";
		const boundary = prefix + "x".repeat(limit - prefix.length - 2) + "*/";
		const accepted = await client.callTool({ name: "code", arguments: { code: boundary } });
		assert.equal(accepted.isError, undefined, JSON.stringify(accepted));
		assert.equal(accepted.structuredContent.result, 1);
		const rejected = await client.callTool({ name: "code", arguments: { code: boundary + " " } });
		assert.equal(rejected.isError, true);
		assert.match(rejected.content[0].text, /too_big|Too big|1000000/);
	});
});

test("serves the code tool over the modern MCP protocol", async () => {
	await withMcpClient(
		{
			versionNegotiation: {
				mode: { pin: MODERN_PROTOCOL_VERSION },
			},
		},
		async (client) => {
			assert.equal(client.getNegotiatedProtocolVersion(), MODERN_PROTOCOL_VERSION);
			assert.equal(client.getServerCapabilities().tools.listChanged, false);
			assert.deepEqual(client.getServerVersion().icons, MCP_ICONS);
			const { tools } = await client.listTools();
			assert.equal(tools.length, 1);
			const [tool] = tools;
			assert.equal(tool.name, "code");
			assert.equal(tool.icons, undefined);
			assert.match(tool.description ?? "", /codemode\.search.*connector method names/s);
			const connectorSection = (tool.description ?? "").split("## Available connectors\n")[1]?.split("\n## ")[0];
			assert.ok(connectorSection);

			for (const name of ["cloudflare", "google", "maps", "unifi", "twilio", "exa", "kalshi"]) {
				assert.match(connectorSection, new RegExp("- `" + name + "`"));
			}

			assert.match(connectorSection, /Routes API/);
			assert.match(connectorSection, /JPEG camera snapshots/);
			assert.doesNotMatch(tool.description ?? "", /notion/i);
			assert.match(tool.description ?? "", /Search first for the task capability/);
			assert.match(tool.description ?? "", /Prefer a purpose-specific API connector/);
			assert.match(tool.description ?? "", /search for `maps directions`/);
			assert.doesNotMatch(tool.description ?? "", /to read reviews from a Google Maps page|Do not search for `Google Maps reviews`/);
			assert.match(tool.description ?? "", /failed code invocation does not undo earlier connector calls/);
			assert.match(tool.description ?? "", /outcome=unknown/);
			assert.match(tool.description ?? "", /use native API pagination inside the function/);
			assert.match(tool.description ?? "", /Do not treat truncated output as complete or reuse a truncated identifier or cursor/);
			assert.match(tool.description ?? "", /Return connector image values unchanged/);
			assert.match(tool.description ?? "", /At most 4 images totaling 4 MiB/);
			assert.deepEqual(tool.annotations, {
				destructiveHint: true,
				idempotentHint: false,
				openWorldHint: true,
				readOnlyHint: false,
			});
			assert.deepEqual(tool.outputSchema?.required, ["result"]);

			const discovery = await client.callTool({
				name: "code",
				arguments: { code: 'async () => await codemode.search("gmail email settings")' },
			});

			assert.equal(discovery.isError, undefined);
			assert.equal(discovery.structuredContent.result.results[0].path, "google.request");

			for (const query of ["maps directions", "google maps", "route distance", "business ratings"]) {
				const matches = await client.callTool({ name: "code", arguments: { code: `async () => await codemode.search(${JSON.stringify(query)})` } });
				assert.equal(matches.isError, undefined);
				assert.equal(matches.structuredContent.result.results[0].path, "maps.request", query);
			}

			const result = await client.callTool({
				name: "code",
				arguments: {
					code: 'async () => ({ first: 1, second: "two" })',
				},
			});

			assert.deepEqual(result.structuredContent, {
				result: { first: 1, second: "two" },
			});
			assert.deepEqual(JSON.parse(result.content[0].text), {
				first: 1,
				second: "two",
			});
		},
	);
});

test("retains legacy MCP compatibility", async () => {
	await withMcpClient(undefined, async (client) => {
		assert.equal(client.getNegotiatedProtocolVersion(), LEGACY_PROTOCOL_VERSION);
		assert.equal(client.getServerCapabilities().tools.listChanged, false);
		assert.deepEqual(client.getServerVersion().icons, MCP_ICONS);
		const { tools } = await client.listTools();
		assert.deepEqual(
			tools.map((tool) => tool.name),
			["code"],
		);
		assert.equal(tools[0].icons, undefined);

		const result = await client.callTool({
			name: "code",
			arguments: { code: 'async () => "legacy"' },
		});

		assert.deepEqual(result.structuredContent, { result: "legacy" });
	});
});

test("does not promise unsupported change notifications to modern subscribers", async () => {
	for (const notifications of [
		{ toolsListChanged: true },
		{ promptsListChanged: true },
		{ resourcesListChanged: true },
		{ resourceSubscriptions: ["file:///example"] },
		{},
	]) {
		const response = await debugServer.getWorker("concierge").fetch(debugMcpUrl, {
			method: "POST",
			headers: {
				Accept: "application/json, text/event-stream",
				"Content-Type": "application/json",
				"MCP-Protocol-Version": MODERN_PROTOCOL_VERSION,
				"Mcp-Method": "subscriptions/listen",
			},
			body: JSON.stringify({
				jsonrpc: "2.0", id: 7, method: "subscriptions/listen",
				params: {
					notifications,
					_meta: {
						"io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
						"io.modelcontextprotocol/clientInfo": { name: "concierge-integration-test", version: "1.0.0" },
						"io.modelcontextprotocol/clientCapabilities": {},
					},
				},
			}),
		});

		assert.equal(response.status, 200);
		assert.match(response.headers.get("Content-Type"), /text\/event-stream/);
		const reader = response.body.getReader();

		try {
			const { value } = await reader.read();
			const frame = new TextDecoder().decode(value).split("\n").find((line) => line.startsWith("data:"));
			assert.ok(frame);
			const acknowledgment = JSON.parse(frame.slice(5));
			assert.equal(acknowledgment.method, "notifications/subscriptions/acknowledged");
			assert.deepEqual(acknowledgment.params.notifications, {});
		} finally {
			await reader.cancel();
		}
	}
});

test("preserves structured large results when Code Mode truncates them", async () => {
	await withMcpClient(undefined, async (client) => {
		const result = await client.callTool({
			name: "code",
			arguments: {
				code: 'async () => ({ title: "Large result", body: "x".repeat(100000) })',
			},
		});

		assert.equal(result.isError, undefined);
		assert.equal(result.structuredContent.result.title, "Large result");
		assert.match(result.structuredContent.result.body, /--- TRUNCATED ---/);
		assert.ok(result.structuredContent.result.body.length < 100000);
		assert.deepEqual(JSON.parse(result.content[0].text), result.structuredContent.result);
	});
});

test("records correlated operational metadata without source, results or exception messages", async () => {
	debugServer.clearLogs();
	await withMcpClient(undefined, async (client) => {
		for (const [code, isError] of [
			['async () => "private returned content"', undefined],
			['async () => { throw new Error("private exception content"); }', true],
			['async () => { invalid syntax private_source_marker }', true],
			["async () => await cloudflare.read_webpage_as_markdown({ url: 'https://example.com/test' })", undefined],
		]) {
			const result = await client.callTool({ name: "code", arguments: { code } });
			assert.equal(result.isError, isError);
		}
	});

	const events = await waitFor(() => {
		const events = usageEvents(debugServer, '{"event":"code_execution"');

		return events.length >= 4 ? events : undefined;
	}, "Code Mode execution telemetry");

	const logs = debugServer.getLogs();
	assert.equal(events.length, 4, JSON.stringify(logs));
	assert.deepEqual(events.map((event) => event.status), ["completed", "error", "error", "completed"]);
	assert.deepEqual(events.map((event) => event.connectorCalls), [0, 0, 0, 1]);
	assert.deepEqual(events.map((event) => event.mcpStatus), ["success", "error", "error", "success"]);
	assert.equal(new Set(events.map((event) => event.invocationId)).size, 4);

	for (const event of events) {
		assert.doesNotThrow(() => z.string().parse(event.executionId));
		assert.ok(Number.isFinite(event.durationMs) && event.durationMs >= 0);
		assert.deepEqual(Object.keys(event).sort(), ["event", "invocationId", "executionId", "durationMs", "status", "mcpStatus", "connectorCalls"].sort());
	}

	const usage = usageEvents(debugServer);
	assert.equal(usage.length, 5);
	assert.doesNotMatch(JSON.stringify(usage), /private returned content|private exception content|private_source_marker|example\.com|networkidle2/);
	const connector = usage.find((event) => event.event === "code_connector_call");
	assert.equal(connector.invocationId, events[3].invocationId);
	assert.equal(connector.executionId, events[3].executionId);
	assert.equal(connector.connector, "cloudflare");
	assert.equal(connector.method, "read_webpage_as_markdown");
	assert.equal(connector.status, "success");
	assert.equal(connector.sequence, 0);
	assert.ok(Number.isFinite(connector.durationMs) && connector.durationMs >= 0);
	assert.deepEqual(Object.keys(connector).sort(), ["event", "invocationId", "executionId", "connector", "method", "sequence", "status", "durationMs"].sort());
});

test("keeps Code Mode outcomes unchanged when telemetry fails", async () => {
	const fixture = debugServer.getWorker("mcp-infrastructure-test");

	const run = async (options) => (await fixture.fetch("/", {
		method: "POST", body: JSON.stringify({ action: "telemetry", ...options }),
	})).json();

	for (const status of ["completed", "error", "paused"]) {
		const output = {
			status, executionId: "private execution id",
			result: { secret: "private result" }, error: "private error", logs: ["private sandbox log"],
			calls: [{ seq: 0, connector: "test", method: "request", state: "applied", args: { token: "private token" } }],
		};

		const response = { content: [{ type: "text", text: "client response" }] };

		if (status !== "completed") response.isError = true;

		for (const loggingFailure of [false, true]) {
			const result = await run({ output, response, loggingFailure });
			assert.equal(result.sameReference, true);
			assert.deepEqual(result.result, response);
			assert.equal(result.executions, 1);
			assert.equal(result.logs.length === 0, loggingFailure);

			if (!loggingFailure) {
				const summary = result.logs.find((event) => event.event === "code_execution");
				assert.equal(summary.status, status);
				assert.equal(summary.connectorCalls, 1);
				assert.equal(summary.executionId, output.executionId);
				assert.equal(summary.mcpStatus, status === "completed" ? "success" : "error");
				assert.doesNotMatch(JSON.stringify(result.logs), /private token|private sandbox log|private result|private error|client response/);
			}
		}
	}

	for (const loggingFailure of [false, true]) {
		const result = await run({ throw: true, loggingFailure });
		assert.equal(result.error, "private exception must not be logged");
		assert.equal(result.executions, 1);
		assert.equal(result.logs.length === 0, loggingFailure);

		if (!loggingFailure) {
			const summary = result.logs.find((event) => event.event === "code_execution");
			assert.equal(summary.status, "exception");
			assert.equal(summary.mcpStatus, "exception");
			assert.equal(summary.connectorCalls, 0);
			assert.doesNotMatch(JSON.stringify(result.logs), /private exception must not be logged/);
		}
	}
});

test("excludes all connector and MCP payloads and reports output-assembly failures", async () => {
	const fixture = debugServer.getWorker("mcp-infrastructure-test");

	const run = async (options) => (await fixture.fetch("/", {
		method: "POST", body: JSON.stringify({ action: "telemetry", ...options }),
	})).json();

	const completed = { status: "completed", executionId: "exec-fixture", calls: [], result: true };

	const response = { structuredContent: { result: {
		personal: "private personal data", access_token: "fixture-access-token", nextToken: "native-pagination",
		password: "fixture-password", providerKey: "worker-key-to-redact", image: { type: "image", mimeType: "image/jpeg", data: JPEG_BASE64 },
	} }, content: [{ type: "image", mimeType: "image/jpeg", data: JPEG_BASE64 }] };

	const recorded = await run({ output: completed, response });
	assert.deepEqual(recorded.result, response, "Logging must not mutate the client-visible response.");
	assert.equal(recorded.logs.length, 1);
	const logs = JSON.stringify(recorded.logs);
	assert.doesNotMatch(logs, /private personal data|native-pagination|fixture-access-token|fixture-password|worker-key-to-redact/);
	assert.ok(!logs.includes(JPEG_BASE64));
	const large = "\u00e9".repeat(80_000);

	const oversized = await run({
		output: { ...completed, calls: Array.from({ length: 40 }, (_, seq) => ({
			seq, connector: "test", method: "request", state: "applied", args: { query: large }, result: { body: large },
		})) }, response: { structuredContent: { result: large } },
	});

	const totalBytes = oversized.logs.reduce((total, event) => total + Buffer.byteLength(JSON.stringify(event)), 0);
	assert.ok(totalBytes < 16 * 1024, totalBytes);
	assert.equal(oversized.logs.length, 41);
	const summary = oversized.logs.at(-1);
	assert.equal(summary.event, "code_execution");
	assert.equal(summary.connectorCalls, 40);
	assert.doesNotMatch(JSON.stringify(oversized.logs), /payload|query|body|\u00e9/);
	assert.equal(oversized.result.structuredContent.result, large);
	const failedOutput = await run({ output: completed, formatThrow: true });
	assert.equal(failedOutput.executions, 1);
	assert.equal(failedOutput.error, "output formatting failure");
	assert.equal(failedOutput.logs.at(-1).status, "completed");
	assert.equal(failedOutput.logs.at(-1).mcpStatus, "exception");
});

test("traces execution and connector outcomes without replaying work when tracing fails", async () => {
	const fixture = debugServer.getWorker("mcp-infrastructure-test");

	const output = { status: "completed", executionId: "exec-trace-fixture", calls: [
		{ seq: 0, connector: "test", method: "request", state: "applied", args: {}, result: { ok: true } },
	] };

	const run = async (options) => (await fixture.fetch("/", {
		method: "POST", body: JSON.stringify({ action: "telemetry", output, response: { isError: true }, ...options }),
	})).json();

	const recorded = await run({ mockTracing: true });
	assert.deepEqual(recorded.spans.map((span) => span.name), ["mcp.code", "connector.test.request"]);
	assert.deepEqual(recorded.spans.map((span) => span.status.code), ["error", "ok"]);
	const summary = recorded.logs.at(-1);
	assert.equal(summary.status, "completed");
	assert.equal(summary.mcpStatus, "error");

	for (const span of recorded.spans) {
		assert.equal(span.attributes["concierge.invocation_id"], summary.invocationId);
		assert.equal(span.attributes["concierge.execution_id"], output.executionId);
		assert.doesNotMatch(JSON.stringify(span.attributes), /payload|args|result|async/);
	}

	for (const tracingFailure of ["before", "after"]) {
		const success = await run({ tracingFailure, response: { content: [{ type: "text", text: "unchanged" }] } });
		assert.equal(success.executions, 1);
		assert.equal(success.sameReference, true);
		assert.equal(success.logs.filter((event) => event.event === "code_connector_call").length, 1);
		assert.equal(success.logs.filter((event) => event.event === "code_execution").length, 1);
		const failed = await run({ tracingFailure, connectorThrow: "provider rejected operation" });
		assert.equal(failed.executions, 1);
		assert.equal(failed.error, "provider rejected operation");
		assert.equal(failed.logs.filter((event) => event.event === "code_connector_call").length, 1);
		assert.equal(failed.logs.find((event) => event.event === "code_connector_call").status, "error");
		assert.equal(failed.logs.at(-1).connectorCalls, 1);
	}
});

test("keeps usage correlation isolated across concurrent MCP invocations", async () => {
	debugServer.clearLogs();
	const originalFetch = globalThis.fetch;
	globalThis.fetch = async (input, init) => {
		const url = new URL(new Request(input, init).url);

		if (url.hostname !== "api.ui.com") return originalFetch(input, init);
		await new Promise((resolve) => setTimeout(resolve, 10));

		return Response.json({ marker: url.searchParams.get("marker") });
	};

	try {
		await withMcpClient(undefined, async (client) => {
			const results = await Promise.all(["first", "second"].map((marker) => client.callTool({ name: "code", arguments: {
				code: `async () => await unifi.request({ method: 'GET', path: '/v1/hosts', query: { marker: '${marker}' } })`,
			} })));

			assert.deepEqual(results.map((result) => result.structuredContent.result.marker), ["first", "second"]);
		});

		const events = await waitFor(() => {
			const events = usageEvents(debugServer);

			return events.filter((event) => event.event === "code_execution").length === 2 ? events : undefined;
		}, "concurrent usage summaries");

		const calls = events.filter((event) => event.event === "code_connector_call");
		assert.equal(new Set(calls.map((event) => event.invocationId)).size, 2);
		assert.equal(new Set(calls.map((event) => event.executionId)).size, 2);

		for (const call of calls) {
			const summary = events.find((event) => event.event === "code_execution" && event.invocationId === call.invocationId);
			assert.equal(summary.executionId, call.executionId);
			assert.equal(summary.connectorCalls, 1);
			assert.equal(summary.mcpStatus, "success");
			assert.equal(call.sequence, 0);
		}

		assert.doesNotMatch(JSON.stringify(events), /first|second|marker|query/);
	} finally { globalThis.fetch = originalFetch; }
});

test("omits credentials and personal data from real MCP operational logs", async () => {
	debugServer.clearLogs();
	await withMcpClient(undefined, async (client) => {
		const result = await client.callTool({ name: "code", arguments: { code: `async () => ({
			personal: 'personal payload fixture', providerKey: '${TEST_SECRETS.UNIFI_API_KEY}',
			token: 'unknown-token-fixture', client_secret: '${TEST_SECRETS.ACCESS_CLIENT_SECRET}',
			nextToken: 'next-page-fixture', password: 'password-with-"quote-fixture'
		})` } });

		assert.equal(result.structuredContent.result.providerKey, TEST_SECRETS.UNIFI_API_KEY);
	});

	const events = await waitFor(() => {
		const events = usageEvents(debugServer);

		return events.some((event) => event.event === "code_execution") ? events : undefined;
	}, "metadata-only usage logs");

	const logs = JSON.stringify(events);
	assert.equal(events.length, 1);
	assert.doesNotMatch(logs, /personal payload fixture|next-page-fixture|test-unifi-api-key|test-access-secret|unknown-token-fixture|quote-fixture/);
});

test("keeps record identity, status and pagination usable in truncated list results", async () => {
	await withMcpClient(undefined, async (client) => {
		const result = await client.callTool({ name: "code", arguments: {
			code: `async () => ({
				items: Array.from({ length: 1000 }, (_, i) => ({ id: "record-" + i, status: i % 2 ? "pending" : "done", body: "x".repeat(1000) })),
				next_cursor: "next-page-1000", has_more: true
			})`,
		} });

		assert.equal(result.isError, undefined);
		const page = result.structuredContent.result;
		assert.equal(page.next_cursor, "next-page-1000");
		assert.equal(page.has_more, true);
		assert.ok(JSON.stringify(page).length <= 24_000);
		assert.match(page.items.at(-1), /--- TRUNCATED ---.*more items/);
		const records = page.items.slice(0, -1);
		assert.ok(records.length > 0 && records.length < 1000);

		for (const [i, record] of records.entries()) {
			assert.equal(record.id, `record-${i}`);
			assert.equal(record.status, i % 2 ? "pending" : "done");
			assert.match(JSON.stringify(record), /--- TRUNCATED ---/);
		}

		assert.deepEqual(JSON.parse(result.content[0].text), page);
	});
});

test("returns projected native pages unchanged without truncation", async () => {
	await withMcpClient(undefined, async (client) => {
		const result = await client.callTool({ name: "code", arguments: {
			code: `async () => {
				const page = { items: Array.from({ length: 10 }, (_, i) => ({ id: "record-" + i, status: "done", body: "x".repeat(1000) })), next_cursor: "next-page-10", has_more: true };
				return { ...page, items: page.items.map(({ id, status }) => ({ id, status })) };
			}`,
		} });

		assert.equal(result.isError, undefined);

		const expected = {
			items: Array.from({ length: 10 }, (_, i) => ({ id: `record-${i}`, status: "done" })),
			next_cursor: "next-page-10", has_more: true,
		};

		assert.deepEqual(result.structuredContent.result, expected);
		assert.deepEqual(JSON.parse(result.content[0].text), expected);
		assert.doesNotMatch(JSON.stringify(result), /--- TRUNCATED ---/);
	});
});

test("calls Browser Run through the Cloudflare connector", async () => {
	await withMcpClient(undefined, async (client) => {
		const result = await client.callTool({
			name: "code",
			arguments: {
				code: "async () => await cloudflare.read_webpage_as_markdown({ url: 'https://example.com/test' })",
			},
		});

		assert.equal(result.isError, undefined);
		const page = result.structuredContent.result;
		assert.equal(page.markdown, "# Mock webpage\nURL: https://example.com/test\nWait: networkidle2\nSelector: none\nSelector timeout: none");
		assert.equal(page.requestedUrl, "https://example.com/test");
		assert.equal(page.finalUrl, "https://example.com/final");
		assert.equal(page.title, "Mock webpage");
		assert.equal(page.status, 200);
		assert.ok(Number.isFinite(Date.parse(page.retrievedAt)));
		assert.equal(page.contentHash, createHash("sha256").update(page.markdown).digest("hex"));
		assert.equal(page.offset, 0);
		assert.equal(page.totalChars, page.markdown.length);
		assert.equal(page.nextOffset, null);
		assert.equal(page.truncated, false);
		assert.doesNotMatch(JSON.stringify(result), /private-test-cookie|set-cookie/);
		assert.deepEqual(JSON.parse(result.content[0].text), page);
	});
});

test("uses bounded browser readiness overrides and represents missing metadata honestly", async () => {
	await withMcpClient(undefined, async (client) => {
		const invoke = (args) => client.callTool({ name: "code", arguments: { code: `async () => await cloudflare.read_webpage_as_markdown(${JSON.stringify(args)})` } });

		for (const waitUntil of ["domcontentloaded", "load", "networkidle0", "networkidle2"]) {
			const result = await invoke({ url: "https://example.com/test", waitUntil, waitForSelector: { selector: "#ready", timeout: 500 } });
			assert.equal(result.isError, undefined);
			assert.match(result.structuredContent.result.markdown, new RegExp(`Wait: ${waitUntil}\\nSelector: #ready\\nSelector timeout: 500`));
		}

		const defaultTimeout = await invoke({ url: "https://example.com/test", waitForSelector: { selector: "main" } });
		assert.match(defaultTimeout.structuredContent.result.markdown, /Selector timeout: 10000/);
		const missing = await invoke({ url: "https://example.com/no-metadata" });
		assert.equal(missing.isError, undefined);

		for (const key of ["finalUrl", "title", "status"]) assert.equal(missing.structuredContent.result[key], null);
	});
});

test("rejects empty, HTTP-error and recognizable gated browser pages without leaking their bodies", async () => {
	await withMcpClient(undefined, async (client) => {
		for (const [path, message] of [["empty", /no readable Markdown/], ["not-found", /HTTP 404/], ["challenge", /require login or a browser challenge/], ["login", /require login or a browser challenge/], ["gate-message", /require login or a browser challenge/]]) {
			const result = await client.callTool({ name: "code", arguments: { code: `async () => await cloudflare.read_webpage_as_markdown({ url: 'https://example.com/${path}' })` } });
			assert.equal(result.isError, true, path);
			assert.match(result.content[0].text, message);
			assert.doesNotMatch(JSON.stringify(result), /Private upstream error|private-test-cookie/);
		}

		const article = await client.callTool({ name: "code", arguments: { code: "async () => await cloudflare.read_webpage_as_markdown({ url: 'https://example.com/login-article' })" } });
		assert.equal(article.isError, undefined);
	});
});

test("paginates fresh browser reads without losing content or silently mixing versions", async () => {
	await withMcpClient(undefined, async (client) => {
		const invoke = (args) => client.callTool({ name: "code", arguments: { code: `async () => await cloudflare.read_webpage_as_markdown(${JSON.stringify(args)})` } });
		const url = "https://example.com/long";
		let offset = 0;
		let contentHash;
		let text = "";

		do {
			const result = await invoke({ url, offset, contentHash });
			assert.equal(result.isError, undefined);
			assert.doesNotMatch(JSON.stringify(result), /--- TRUNCATED ---/);
			const page = result.structuredContent.result;
			assert.equal(page.offset, offset);
			assert.equal(page.totalChars, 30_000);
			assert.equal(page.truncated, true);
			assert.equal(page.contentHash, createHash("sha256").update("0123456789".repeat(3_000)).digest("hex"));
			text += page.markdown;
			offset = page.nextOffset;
			contentHash = page.contentHash;
		} while (offset !== null);

		assert.equal(text, "0123456789".repeat(3_000));

		for (const args of [{ url, offset: 1 }, { url, offset: 30_000, contentHash }, { url, contentHash: "0".repeat(64) }]) {
			assert.equal((await invoke(args)).isError, true);
		}

		const changedUrl = "https://example.com/changing";
		const first = (await invoke({ url: changedUrl, maxChars: 3 })).structuredContent.result;
		const changed = await invoke({ url: changedUrl, offset: first.nextOffset, contentHash: first.contentHash });
		assert.equal(changed.isError, true);
		assert.match(changed.content[0].text, /changed between reads/);
		const escaped = await invoke({ url: "https://example.com/escaped" });
		assert.equal(escaped.isError, undefined);
		assert.doesNotMatch(JSON.stringify(escaped), /--- TRUNCATED ---/);
		assert.equal(escaped.structuredContent.result.nextOffset, escaped.structuredContent.result.markdown.length);
		const oversized = await invoke({ url: "https://example.com/oversized-metadata" });
		assert.equal(oversized.isError, true);
		assert.match(oversized.content[0].text, /source metadata exceeds the output budget/);
		const emoji = await invoke({ url: "https://example.com/unicode", maxChars: 2 });
		assert.equal(emoji.structuredContent.result.markdown, "\uD83D\uDE00");
		assert.equal(emoji.structuredContent.result.nextOffset, 2);
		const rest = await invoke({ url: "https://example.com/unicode", offset: 2, contentHash: emoji.structuredContent.result.contentHash });
		assert.equal(rest.structuredContent.result.markdown, "xyz");
	});
});

test("exposes generated connector contracts and validates browser inputs", async () => {
	await withMcpClient(undefined, async (client) => {
		const docs = await client.callTool({ name: "code", arguments: {
			code: "async () => ({ google: await codemode.describe('google.request'), browser: await codemode.describe('cloudflare.read_webpage_as_markdown') })",
		} });

		assert.equal(docs.isError, undefined);
		assert.match(JSON.stringify(docs.structuredContent.result.google), /GET.*POST.*PATCH.*DELETE/s);
		assert.match(JSON.stringify(docs.structuredContent.result.google), /gmail/);
		assert.match(JSON.stringify(docs.structuredContent.result.browser), /url/);

		for (const args of [null, {}, { url: "" }, { url: "not-a-url" }, { url: "ftp://example.com" }, { url: "https://user:password@example.com" }, { url: "https://example.com", extra: true }, ...[
			{ waitUntil: "never" }, { waitForSelector: { selector: "" } }, { waitForSelector: { selector: "main", timeout: 10_001 } },
			{ waitForSelector: { selector: "main", hidden: true } }, { offset: -1 }, { offset: 0.5 }, { maxChars: 0 }, { maxChars: 1 }, { maxChars: 12_001 },
			{ contentHash: "invalid" }, { cookies: [] }, { setExtraHTTPHeaders: {} }, { cacheTTL: 60 }, { bestAttempt: true },
		].map((args) => ({ url: "https://example.com", ...args }))]) {
			const result = await client.callTool({ name: "code", arguments: {
				code: `async () => await cloudflare.read_webpage_as_markdown(${JSON.stringify(args)})`,
			} });

			assert.equal(result.isError, true, JSON.stringify(args));
		}
	});
});

test("does not expose the removed Notion connector", async () => {
	await withMcpClient(undefined, async (client) => {
		const result = await client.callTool({ name: "code", arguments: {
			code: "async () => ({ matches: await codemode.search('notion'), available: typeof notion !== 'undefined' })",
		} });

		assert.equal(result.isError, undefined);
		assert.ok(result.structuredContent.result.matches.results.every((match) => match.connector !== "notion"));
		assert.equal(result.structuredContent.result.available, false);

		const removedCall = await client.callTool({ name: "code", arguments: {
			code: "async () => await notion.request({ method: 'GET', path: '/v1/users/me' })",
		} });

		assert.equal(removedCall.isError, true);
	});
});

test("rejects invalid Google request arguments before outbound calls", async () => {
	const originalFetch = globalThis.fetch;
	let outboundCalls = 0;
	globalThis.fetch = async (input, init) => {
		const request = new Request(input, init);

		if (["gmail.googleapis.com", "oauth2.googleapis.com"].includes(new URL(request.url).hostname)) {
			outboundCalls++;

			return Response.json({});
		}

		return originalFetch(input, init);
	};

	try {
		await withMcpClient(undefined, async (client) => {
			for (const fields of ["query: { value: NaN }", "query: { value: Infinity }", "query: { value: {} }", "query: { values: [{}] }", "body: {}", "extra: true", "method: 'TRACE'"]) {
				const result = await client.callTool({ name: "code", arguments: {
					code: `async () => await google.request({ service: 'gmail', method: 'GET', path: '/gmail/v1/users/me/profile', ${fields} })`,
				} });

				assert.equal(result.isError, true, fields);
			}
		});
		assert.equal(outboundCalls, 0);
	} finally {
		globalThis.fetch = originalFetch;
	}
});

test("discovers Exa and preserves native search, contents, answers and resource requests", async () => {
	const originalFetch = globalThis.fetch;

	const cases = [
		{ options: { method: "POST", path: "/search", body: { query: "Cloudflare Workers", type: "auto", numResults: 1, includeDomains: ["developers.cloudflare.com"], contents: { highlights: true, text: { maxCharacters: 1000 } }, outputSchema: { type: "object", properties: { title: { type: "string" } } } } }, result: { requestId: "search-id", results: [{ url: "https://developers.cloudflare.com/workers/", title: "Workers", highlights: ["A source excerpt"], publishedDate: "2026-10-01", score: 0.9 }], costDollars: { total: 0.005 }, warnings: [{ tag: "fixture-warning" }] } },
		{ options: { method: "POST", path: "/contents", body: { urls: ["https://example.com/page", "https://example.com/missing"], text: { maxCharacters: 500 }, maxAgeHours: 0 } }, result: { results: [{ url: "https://example.com/page", text: "Native source text" }], statuses: [{ id: "https://example.com/page", status: "success" }, { id: "https://example.com/missing", status: "error", error: { tag: "CRAWL_NOT_FOUND" } }] } },
		{ options: { method: "POST", path: "/findSimilar", body: { url: "https://example.com/page", numResults: 1 } }, result: { results: [{ url: "https://example.org/similar" }] } },
		{ options: { method: "POST", path: "/answer", body: { query: "What is Workers?", stream: false } }, result: { answer: "An answer", citations: [{ url: "https://developers.cloudflare.com/workers/", title: "Workers" }] } },
		{ options: { method: "POST", path: "/agent/runs", body: { query: "Research a topic", outputSchema: { type: "object", properties: { facts: { type: "array", items: { type: "string" } } } } } }, result: { id: "run-fixture", status: "queued", costDollars: null } },
		{ options: { method: "GET", path: "/agent/runs/run-fixture/events", query: { cursor: "native+cursor", limit: 1 } }, result: { data: [{ id: "event-id", type: "run.completed" }], nextCursor: "next+cursor", hasMore: true } },
		{ options: { method: "POST", path: "/monitors", body: { name: "Updates", search: { query: "Updates", numResults: 1 } } }, result: { id: "monitor-id", status: "active" } },
		{ options: { method: "PATCH", path: "/monitors/monitor-id", body: { status: "paused" } }, result: { id: "monitor-id", status: "paused" } },
		{ options: { method: "GET", path: "/batches", query: { limit: 1 } }, result: { data: [], hasMore: false } },
		{ options: { method: "DELETE", path: "/agent/runs/run-fixture" }, result: null },
	];

	let current;
	let calls = 0;
	let dispatchFailure;
	globalThis.fetch = async (input, init) => {
		const request = new Request(input, init);
		const url = new URL(request.url);

		if (url.hostname !== "api.exa.ai") return originalFetch(input, init);
		calls++;

		try {
			assert.equal(request.headers.get("Authorization"), `Bearer ${TEST_SECRETS.EXA_API_KEY}`);
			assert.equal(request.headers.get("Accept"), "application/json");
			assert.equal(request.headers.has("X-API-Key"), false);
			assert.equal(request.headers.has("X-Goog-Api-Key"), false);
			assert.equal(request.method, current.options.method);
			assert.equal(url.pathname, current.options.path);
			assert.deepEqual(Object.fromEntries(url.searchParams), Object.fromEntries(Object.entries(current.options.query ?? {}).map(([k, v]) => [k, String(v)])));

			if (current.options.body !== undefined) {
				assert.equal(request.headers.get("Content-Type"), "application/json");
				assert.deepEqual(await request.json(), current.options.body);
			} else assert.equal(await request.text(), "");

			return current.result === null ? new Response(null, { status: 204 }) : Response.json(current.result);
		} catch (error) { dispatchFailure = error; throw error; }
	};

	try {
		await withMcpClient(undefined, async (client) => {
			assert.match((await client.listTools()).tools[0].description, /exa\.request/);

			for (const query of ["exa", "external web search", "page content extraction", "similar links", "cited answers"]) {
				const result = await client.callTool({ name: "code", arguments: { code: `async () => await codemode.search(${JSON.stringify(query)})` } });
				assert.ok(result.structuredContent.result.results.some((match) => match.path === "exa.request"), query);
			}

			const docs = await client.callTool({ name: "code", arguments: { code: "async () => await codemode.describe('exa.request')" } });
			assert.match(JSON.stringify(docs), /per-URL statuses/);
			assert.match(JSON.stringify(docs), /30-second/);

			for (current of cases) {
				const result = await client.callTool({ name: "code", arguments: { code: `async () => await exa.request(${JSON.stringify(current.options)})` } });

				if (dispatchFailure) throw dispatchFailure;
				assert.equal(result.isError, undefined, JSON.stringify(result));
				assert.deepEqual(result.structuredContent.result, current.result);
				assert.deepEqual(JSON.parse(result.content[0].text), current.result);
				assert.ok(!JSON.stringify(result).includes(TEST_SECRETS.EXA_API_KEY));
			}
		});
		assert.equal(calls, cases.length);
	} finally { globalThis.fetch = originalFetch; }
});

test("Exa rejects credential overrides, alternate origins, invalid bodies and streaming before dispatch", async () => {
	const originalFetch = globalThis.fetch;
	let calls = 0;
	globalThis.fetch = async (input, init) => {
		if (!new URL(new Request(input, init).url).hostname.endsWith("exa.ai")) return originalFetch(input, init);
		calls++;

		return Response.json({ unexpected: true });
	};

	try {
		await withMcpClient(undefined, async (client) => {
			const base = { method: "POST", path: "/search", body: { query: "fixture" } };

			for (const override of [
				{ method: "OPTIONS" }, { apiKey: "override" }, { headers: { Authorization: "Bearer override" } },
				{ url: "https://api.exa.ai/search" }, { path: "https://api.exa.ai/search" },
				{ path: "//admin-api.exa.ai/team-management/api-keys" }, { path: "/search?api_key=override" },
				{ path: "/%2fsearch" }, { path: "/%25search" }, { path: "/agent//runs" },
				{ query: { api_key: "override" } }, { query: { limit: {} } }, { body: [] }, { body: null }, { body: "not an object" },
				{ method: "GET", body: {} }, { body: { query: "fixture", stream: true } },
				{ query: { stream: true } }, { query: { stream: "true" } }, { query: { stream: ["true"] } },
			]) {
				const result = await client.callTool({ name: "code", arguments: { code: `async () => await exa.request(${JSON.stringify({ ...base, ...override })})` } });
				assert.equal(result.isError, true, JSON.stringify(override));
			}
		});
		assert.equal(calls, 0);
	} finally { globalThis.fetch = originalFetch; }
});

test("Exa retries known retrievals but never replays resource mutations", async () => {
	const originalFetch = globalThis.fetch;
	let calls = 0;
	let status = 503;
	let recover = true;
	globalThis.fetch = async (input, init) => {
		if (new URL(new Request(input, init).url).hostname !== "api.exa.ai") return originalFetch(input, init);
		calls++;

		if (recover && calls > 1) return Response.json({ results: [] });

		return Response.json({ tag: "SERVICE_OVERLOADED", requestId: "exa-request-id", error: `Provider error ${TEST_SECRETS.EXA_API_KEY}` }, { status, headers: { "Retry-After": "0" } });
	};

	try {
		await withMcpClient(undefined, async (client) => {
			const invoke = (options) => client.callTool({ name: "code", arguments: { code: `async () => await exa.request(${JSON.stringify(options)})` } });

			for (const path of ["/search", "/contents", "/findSimilar", "/answer"]) {
				calls = 0;
				const result = await invoke({ method: "POST", path, body: { fixture: true } });
				assert.equal(result.isError, undefined, JSON.stringify(result));
				assert.equal(calls, 2, path);
			}

			calls = 0;
			status = 429;
			assert.equal((await invoke({ method: "GET", path: "/agent/runs/fixture" })).isError, undefined);
			assert.equal(calls, 2);
			recover = false;

			for (status of [429, 503]) for (const options of [
				{ method: "POST", path: "/agent/runs", body: { query: "fixture" } },
				{ method: "POST", path: "/batches", body: {} },
				{ method: "POST", path: "/monitors", body: {} },
				{ method: "PATCH", path: "/monitors/fixture", body: { status: "paused" } },
				{ method: "DELETE", path: "/agent/runs/fixture" },
				{ method: "PUT", path: "/search", body: {} },
			]) {
				calls = 0;
				const result = await invoke(options);
				assert.equal(result.isError, true);
				assert.equal(calls, 1, JSON.stringify(options));
				assert.match(result.content[0].text, /safe_to_replay=false/);
				assert.match(result.content[0].text, status === 503 ? /outcome=unknown/ : /outcome=rejected/);
				assert.match(result.content[0].text, /code=SERVICE_OVERLOADED.*request_id=exa-request-id/);
				assert.doesNotMatch(JSON.stringify(result), /test-exa-api-key/);
			}
		});
	} finally { globalThis.fetch = originalFetch; }
});

test("Exa classifies native errors and preserves billing failures without leaking credentials", async () => {
	const originalFetch = globalThis.fetch;
	let status = 400;
	let payload;
	let calls = 0;
	globalThis.fetch = async (input, init) => {
		if (new URL(new Request(input, init).url).hostname !== "api.exa.ai") return originalFetch(input, init);
		calls++;

		return Response.json(payload, { status });
	};

	try {
		await withMcpClient(undefined, async (client) => {
			for (status of [400, 401, 402, 403]) {
				calls = 0;
				payload = { requestId: `request-${TEST_SECRETS.EXA_API_KEY}`, tag: status === 402 ? "NO_MORE_CREDITS" : "INVALID_REQUEST_BODY", error: `Provider error ${TEST_SECRETS.EXA_API_KEY}` };
				const result = await client.callTool({ name: "code", arguments: { code: "async () => await exa.request({ method: 'POST', path: '/search', body: { query: 'fixture' } })" } });
				assert.equal(result.isError, true);
				assert.equal(calls, 1);
				assert.match(result.content[0].text, new RegExp(`HTTP ${status}`));
				assert.match(result.content[0].text, /retryable=false/);
				assert.doesNotMatch(JSON.stringify(result), /test-exa-api-key/);

				if (status === 402) assert.match(result.content[0].text, /code=NO_MORE_CREDITS/);

				if (status === 401 || status === 403) assert.doesNotMatch(JSON.stringify(result), /Provider error/);
			}

			status = 400;
			payload = { error: { type: "INVALID_REQUEST", code: "INVALID_OUTPUT_SCHEMA", message: `Bad schema ${TEST_SECRETS.EXA_API_KEY}` } };
			const result = await client.callTool({ name: "code", arguments: { code: "async () => await exa.request({ method: 'POST', path: '/agent/runs', body: { query: 'fixture' } })" } });
			assert.match(result.content[0].text, /code=INVALID_OUTPUT_SCHEMA/);
			assert.doesNotMatch(JSON.stringify(result), /test-exa-api-key/);
		});
	} finally { globalThis.fetch = originalFetch; }
});

test("Exa rejects redirects, SSE, binary and invalid JSON without replaying successful writes", async () => {
	const originalFetch = globalThis.fetch;
	let mode;
	let calls = 0;
	globalThis.fetch = async (input, init) => {
		const url = new URL(new Request(input, init).url);

		if (!["api.exa.ai", "evil.example"].includes(url.hostname)) return originalFetch(input, init);
		assert.equal(url.hostname, "api.exa.ai");
		calls++;

		if (mode === "redirect") return new Response(null, { status: 302, headers: { Location: "https://evil.example/" } });

		if (mode === "network") throw new Error("private network failure test-exa-api-key");

		return new Response("private-response-body", { headers: { "Content-Type": mode === "sse" ? "text/event-stream" : mode === "binary" ? "image/jpeg" : "application/json" } });
	};

	try {
		await withMcpClient(undefined, async (client) => {
			for (mode of ["redirect", "sse", "binary", "json", "network"]) {
				calls = 0;
				const result = await client.callTool({ name: "code", arguments: { code: "async () => await exa.request({ method: 'POST', path: '/agent/runs', body: { query: 'fixture' } })" } });
				assert.equal(result.isError, true);
				assert.equal(calls, 1);
				assert.match(result.content[0].text, mode === "redirect" ? /HTTP 302/ : mode === "network" ? /outcome=unknown/ : /outcome=succeeded/);
				assert.doesNotMatch(JSON.stringify(result), /private-response-body|private network failure|test-exa-api-key/);
			}
		});
	} finally { globalThis.fetch = originalFetch; }
});

test("Exa fails clearly before dispatch when its API key is missing", async () => {
	const harness = createConciergeHarness(true, { EXA_API_KEY: "" });
	const client = new Client({ name: "exa-config-test", version: "1" });
	const originalFetch = globalThis.fetch;
	let calls = 0;
	globalThis.fetch = async (input, init) => {
		if (new URL(new Request(input, init).url).hostname !== "api.exa.ai") return originalFetch(input, init);
		calls++;

		return Response.json({ unexpected: true });
	};

	try {
		const listener = await harness.listen();
		await client.connect(new StreamableHTTPClientTransport(new URL("/debug/mcp", listener.url)));
		const result = await client.callTool({ name: "code", arguments: { code: "async () => await exa.request({ method: 'POST', path: '/search', body: { query: 'fixture' } })" } });
		assert.equal(result.isError, true);
		assert.match(result.content[0].text, /EXA_API_KEY is not configured/);
		assert.equal(calls, 0);
	} finally { globalThis.fetch = originalFetch; await client.close(); await harness.close(); }
});

test("Kalshi discovers authenticated market/account access and preserves native requests and responses", async () => {
	const originalFetch = globalThis.fetch;

	const cases = [
		{ options: { method: "GET", path: "/trade-api/v2/markets", query: { status: "open", limit: 1, cursor: "native+cursor", tickers: ["TEST-A", "TEST-B"] } },
			payload: { markets: [{ ticker: "TEST-A", yes_bid_dollars: "0.5300", yes_ask_dollars: "0.5700", volume_fp: "1234.00", rules_primary: "Fixture rules", future: { native: true } }], cursor: "next+cursor" } },
		{ options: { method: "GET", path: "/trade-api/v2/markets/TEST-A/orderbook", query: { depth: 2 } }, payload: { orderbook_fp: { yes_dollars: [["0.5300", "2.00"]], no_dollars: [["0.4300", "4.00"]] } } },
		{ options: { method: "GET", path: "/trade-api/v2/portfolio/balance" }, payload: { balance: 12345, portfolio_value: 6789 } },
		{ options: { method: "GET", path: "/trade-api/v2/portfolio/positions" }, payload: { market_positions: [{ ticker: "TEST-A", position_fp: "2.00" }], cursor: "" } },
		{ options: { method: "POST", path: "/trade-api/v2/portfolio/orders", body: { ticker: "TEST-A", client_order_id: "fixture-order" } }, payload: { order: { order_id: "fixture-order", status: "resting" } } },
		{ options: { method: "PUT", path: "/trade-api/v2/portfolio/subaccounts/netting", body: { enabled: true, subaccount_number: 1 } }, payload: { updated: true } },
		{ options: { method: "PATCH", path: "/trade-api/v2/portfolio/orders/fixture-order", body: { count_fp: "2.00" } }, payload: { order_id: "fixture-order" } },
		{ options: { method: "DELETE", path: "/trade-api/v2/portfolio/orders/fixture-order" }, payload: null },
	];

	let current;
	let calls = 0;
	let dispatchFailure;
	globalThis.fetch = async (input, init) => {
		const request = new Request(input, init);
		const url = new URL(request.url);

		if (url.hostname !== "external-api.kalshi.com") return originalFetch(input, init);
		calls++;

		try {
			assert.equal(request.method, current.options.method);
			assert.equal(url.pathname, current.options.path);
			assert.equal(request.headers.get("Accept"), "application/json");
			assert.equal(request.headers.get("Authorization"), null);
			assert.equal(request.headers.get("KALSHI-ACCESS-KEY"), TEST_SECRETS.KALSHI_API_KEY_ID);
			const timestamp = request.headers.get("KALSHI-ACCESS-TIMESTAMP");
			assert.match(timestamp, /^\d{13}$/);
			assert.ok(Math.abs(Date.now() - Number(timestamp)) < 5000);
			const message = timestamp + request.method + url.pathname;
			const signature = Buffer.from(request.headers.get("KALSHI-ACCESS-SIGNATURE"), "base64");
			assert.ok(verify(null, Buffer.from(message), KALSHI_KEYS.publicKey, signature));
			assert.equal(verify(null, Buffer.from(message + "?incorrect=query"), KALSHI_KEYS.publicKey, signature), false);

			for (const [key, value] of Object.entries(current.options.query ?? {})) {
				assert.deepEqual(url.searchParams.getAll(key), [value].flat().map(String));
			}

			if (current.options.body === undefined) assert.equal(await request.text(), "");
			else assert.deepEqual(await request.json(), current.options.body);
		} catch (cause) { dispatchFailure = cause; throw cause; }

		return current.payload === null ? new Response(null, { status: 204 }) : Response.json(current.payload);
	};

	try {
		await withMcpClient(undefined, async (client) => {
			const matches = await client.callTool({ name: "code", arguments: { code: "async () => await codemode.search('Kalshi prediction market odds')" } });
			assert.equal(matches.isError, undefined);
			assert.equal(matches.structuredContent.result.results[0].path, "kalshi.request");
			const described = await client.callTool({ name: "code", arguments: { code: "async () => await codemode.describe('kalshi.request')" } });
			assert.equal(described.isError, undefined);
			assert.match(JSON.stringify(described), /key scopes|Key scopes/);
			assert.doesNotMatch(JSON.stringify(described), /test-kalshi-key-id|BEGIN PRIVATE KEY/);

			for (current of cases) {
				const result = await client.callTool({ name: "code", arguments: { code: `async () => await kalshi.request(${JSON.stringify(current.options)})` } });

				if (dispatchFailure) throw dispatchFailure;
				assert.equal(result.isError, undefined, JSON.stringify(result));
				assert.deepEqual(result.structuredContent.result, current.payload);
				assert.deepEqual(JSON.parse(result.content[0].text), current.payload);
			}

			assert.equal(calls, cases.length);
		});
	} finally { globalThis.fetch = originalFetch; }
});

test("Kalshi rejects credential overrides, origin escapes, key-management calls and invalid inputs before dispatch", async () => {
	const originalFetch = globalThis.fetch;
	let calls = 0;
	globalThis.fetch = async (input, init) => {
		if (new URL(new Request(input, init).url).hostname !== "external-api.kalshi.com") return originalFetch(input, init);
		calls++;

		return Response.json({ unexpected: true });
	};

	try {
		await withMcpClient(undefined, async (client) => {
			for (const override of [
				{ method: "OPTIONS" }, { method: "get" }, { body: {} }, { headers: { "KALSHI-ACCESS-KEY": "override" } },
				{ keyId: "override" }, { privateKey: "override" }, { scopes: ["write"] }, { url: "https://evil.example/" },
				{ query: { access_token: "override" } }, { query: { limit: Infinity } },
				...["https://evil.example/trade-api/v2/markets", "https://external-api.kalshi.com/trade-api/v2/markets",
					"/trade-api/v2/../../escape", "/trade-api/v2/%2e%2e/escape", "/trade-api/v2//markets",
					"/trade-api/v2/markets?limit=1", "/trade-api/v2/markets#fragment", "/trade-api/v2/markets%2fother",
					"/trade-api/v2/api_keys", "/trade-api/v2/api_keys/generate", "/trade-api/v2/%61pi_keys",
					"/trade-api/v2/%2561pi_keys"].map((path) => ({ path })),
			]) {
				const options = { method: "GET", path: "/trade-api/v2/markets", ...override };
				const result = await client.callTool({ name: "code", arguments: { code: `async () => await kalshi.request(${JSON.stringify(options)})` } });
				assert.equal(result.isError, true, JSON.stringify(override));
			}

			assert.equal(calls, 0);
		});
	} finally { globalThis.fetch = originalFetch; }
});

test("Kalshi signs with Ed25519 PEM, including escaped newlines", async (t) => {
	const edPem = TEST_SECRETS.KALSHI_PRIVATE_KEY;

	const variants = [
		{ name: "Ed25519 PKCS8", pem: edPem },
		{ name: "Ed25519 escaped newlines", pem: edPem.replaceAll("\n", "\\n") },
	];

	for (const variant of variants) await t.test(variant.name, async () => {
		const harness = createConciergeHarness(true, { KALSHI_PRIVATE_KEY: variant.pem });
		const originalFetch = globalThis.fetch;
		let verified = false;
		globalThis.fetch = async (input, init) => {
			const request = new Request(input, init);
			const url = new URL(request.url);

			if (url.hostname !== "external-api.kalshi.com") return originalFetch(input, init);
			const message = request.headers.get("KALSHI-ACCESS-TIMESTAMP") + request.method + url.pathname;
			verified = verify(null, Buffer.from(message), KALSHI_KEYS.publicKey, Buffer.from(request.headers.get("KALSHI-ACCESS-SIGNATURE"), "base64"));

			return Response.json({ verified });
		};

		try {
			await harness.listen();
			await withMcpClient(undefined, async (client) => {
				const result = await client.callTool({ name: "code", arguments: { code: "async () => await kalshi.request({ method: 'GET', path: '/trade-api/v2/portfolio/balance', query: { subaccount: 1 } })" } });
				assert.equal(result.isError, undefined, JSON.stringify(result));
				assert.equal(verified, true);
			}, harness);
		} finally { globalThis.fetch = originalFetch; await harness.close(); }
	});
});

test("Kalshi refreshes signatures on read retries and never replays mutations", async () => {
	const originalFetch = globalThis.fetch;
	let calls = 0;
	let status = 503;
	let recover = true;
	const timestamps = [];
	const signatures = [];
	globalThis.fetch = async (input, init) => {
		const request = new Request(input, init);

		if (new URL(request.url).hostname !== "external-api.kalshi.com") return originalFetch(input, init);
		calls++;
		timestamps.push(request.headers.get("KALSHI-ACCESS-TIMESTAMP"));
		signatures.push(request.headers.get("KALSHI-ACCESS-SIGNATURE"));

		if (recover && calls === 2) return Response.json({ ok: true });

		return Response.json({ code: "fixture_code", message: `${TEST_SECRETS.KALSHI_API_KEY_ID} ${TEST_SECRETS.KALSHI_PRIVATE_KEY} ${signatures.at(-1)}` },
			{ status, headers: { "Retry-After": "0" } });
	};

	try {
		await withMcpClient(undefined, async (client) => {
			const invoke = (method) => client.callTool({ name: "code", arguments: { code: `async () => await kalshi.request({ method: '${method}', path: '/trade-api/v2/portfolio/orders' })` } });
			assert.equal((await invoke("GET")).isError, undefined);
			assert.equal(calls, 2);
			assert.ok(Number(timestamps[1]) > Number(timestamps[0]));
			assert.notEqual(signatures[0], signatures[1]);
			recover = false;

			for (status of [400, 401, 403, 429, 503]) {
				calls = 0;
				const result = await invoke("POST");
				assert.equal(result.isError, true);
				assert.equal(calls, 1);
				assert.match(result.content[0].text, new RegExp(`HTTP ${status}`));
				assert.match(result.content[0].text, /safe_to_replay=false/);
				assert.match(result.content[0].text, status === 503 ? /outcome=unknown/ : /outcome=rejected/);
				assert.doesNotMatch(JSON.stringify(result), /test-kalshi-key-id|BEGIN PRIVATE KEY/);
				assert.ok(!JSON.stringify(result).includes(signatures.at(-1)));
			}

			assert.doesNotMatch(JSON.stringify(debugServer.getLogs()), /test-kalshi-key-id|BEGIN PRIVATE KEY/);

			for (const signature of signatures) assert.ok(!JSON.stringify(debugServer.getLogs()).includes(signature));
		});
	} finally { globalThis.fetch = originalFetch; }
});

test("Kalshi rejects redirects and non-JSON successes without replaying completed writes", async () => {
	const originalFetch = globalThis.fetch;
	let mode = "redirect";
	let calls = 0;
	let leaked = false;
	globalThis.fetch = async (input, init) => {
		const url = new URL(new Request(input, init).url);

		if (url.hostname === "evil.example") { leaked = true;

 return Response.json({ unexpected: true }); }

		if (url.hostname !== "external-api.kalshi.com") return originalFetch(input, init);
		calls++;

		if (mode === "redirect") return new Response(null, { status: 302, headers: { Location: "https://evil.example/credentials" } });

		return new Response(mode === "json" ? "{" : "private-provider-data", { headers: { "Content-Type": mode === "json" ? "application/json" : "text/html; private=header" } });
	};

	try {
		await withMcpClient(undefined, async (client) => {
			for (mode of ["redirect", "html", "json"]) {
				calls = 0;
				const result = await client.callTool({ name: "code", arguments: { code: "async () => await kalshi.request({ method: 'POST', path: '/trade-api/v2/portfolio/orders', body: {} })" } });
				assert.equal(result.isError, true);
				assert.equal(calls, 1);
				assert.match(result.content[0].text, mode === "redirect" ? /HTTP 302.*outcome=unknown/ : /outcome=succeeded/);
				assert.doesNotMatch(JSON.stringify(result), /private-provider-data|private=header/);
			}

			assert.equal(leaked, false);
		});
	} finally { globalThis.fetch = originalFetch; }
});

test("Kalshi fails before dispatch for missing, malformed or unsupported credentials", async () => {
	const originalFetch = globalThis.fetch;
	let calls = 0;
	globalThis.fetch = async (input, init) => {
		if (new URL(new Request(input, init).url).hostname !== "external-api.kalshi.com") return originalFetch(input, init);
		calls++;

		return Response.json({ unexpected: true });
	};

	try {
		for (const credentials of [
			{ KALSHI_API_KEY_ID: "" }, { KALSHI_PRIVATE_KEY: "" }, { KALSHI_API_KEY_ID: "bad\nheader" },
			{ KALSHI_PRIVATE_KEY: "private-malformed-key" },
			{ KALSHI_PRIVATE_KEY: GOOGLE_KEYS.privateKey.export({ type: "pkcs8", format: "pem" }) },
			{ KALSHI_PRIVATE_KEY: KALSHI_KEYS.publicKey.export({ type: "spki", format: "pem" }) },
		]) {
			const harness = createConciergeHarness(true, credentials);

			try {
				await harness.listen();
				await withMcpClient(undefined, async (client) => {
					const result = await client.callTool({ name: "code", arguments: { code: "async () => await kalshi.request({ method: 'GET', path: '/trade-api/v2/markets' })" } });
					assert.equal(result.isError, true);
					assert.match(result.content[0].text, /KALSHI_API_KEY_ID.*KALSHI_PRIVATE_KEY/);
					assert.doesNotMatch(JSON.stringify(result), /private-malformed-key|BEGIN PRIVATE KEY|bad.*header/);
				}, harness);
			} finally { await harness.close(); }
		}

		assert.equal(calls, 0);
	} finally { globalThis.fetch = originalFetch; }
});

test("discovers Twilio and preserves native messages, form bodies, account paths and pagination", async () => {
	const originalFetch = globalThis.fetch;
	const prefix = `/2010-04-01/Accounts/${TEST_SECRETS.TWILIO_ACCOUNT_SID}`;
	const authorization = `Basic ${Buffer.from(`${TEST_SECRETS.TWILIO_API_KEY_SID}:${TEST_SECRETS.TWILIO_API_KEY_SECRET}`).toString("base64")}`;

	const page = { messages: [{ sid: "SMfixture", body: "Native message", status: "received", price: "-0.01" }],
		next_page_uri: `${prefix}/Messages.json?PageToken=native%2Btoken&PageSize=1`, page: 0, page_size: 1 };

	const cases = [
		{ options: { method: "GET", path: "/2010-04-01/Accounts/{AccountSid}/Messages.json", query: { PageSize: 1, "DateSent>=": "2026-10-01", To: "+15555550123" } }, result: page },
		{ options: { method: "GET", path: `${prefix}/Messages.json`, query: { PageToken: "native+token", PageSize: 1 } }, result: { ...page, next_page_uri: null, page: 1 } },
		{ options: { method: "POST", path: "/2010-04-01/Accounts/{AccountSid}/Messages.json", body: { To: "+15555550123", From: "+15555550456", Body: "A + B & C", MediaUrl: ["https://example.com/one.jpg", "https://example.com/two.jpg"], ProvideFeedback: true, MaxPrice: 0.05 } }, result: { sid: "SMsent", status: "queued", error_code: null } },
		{ options: { method: "POST", path: `${prefix}/Calls.json`, body: { To: "+15555550123", From: "+15555550456", Twiml: '<Response><Say>Hello</Say></Response>' } }, result: { sid: "CAfixture", status: "queued" } },
		{ options: { method: "GET", path: `${prefix}/IncomingPhoneNumbers.json` }, result: { incoming_phone_numbers: [] } },
		{ options: { method: "GET", path: `${prefix}/Usage/Records/Today.json` }, result: { usage_records: [{ category: "sms", count: "2" }] } },
		{ options: { method: "DELETE", path: `${prefix}/Messages/SMfixture.json` }, result: null },
	];

	let current;
	let calls = 0;
	let dispatchFailure;
	globalThis.fetch = async (input, init) => {
		const request = new Request(input, init);
		const url = new URL(request.url);

		if (url.hostname !== "api.twilio.com") return originalFetch(input, init);
		calls++;

		try {
			assert.equal(request.headers.get("Authorization"), authorization);
			assert.equal(request.headers.get("Accept"), "application/json");
			assert.equal(request.headers.has("X-API-Key"), false);
			assert.equal(request.headers.has("X-Goog-Api-Key"), false);
			assert.equal(request.method, current.options.method);
			assert.equal(url.pathname, current.options.path.replace("{AccountSid}", TEST_SECRETS.TWILIO_ACCOUNT_SID));
			assert.deepEqual(Object.fromEntries(url.searchParams), Object.fromEntries(Object.entries(current.options.query ?? {}).map(([k, v]) => [k, String(v)])));

			if (current.options.body !== undefined) {
				assert.equal(request.headers.get("Content-Type"), "application/x-www-form-urlencoded");
				const body = new URLSearchParams(await request.text());

				for (const [key, value] of Object.entries(current.options.body))
					assert.deepEqual(body.getAll(key), (Array.isArray(value) ? value : [value]).map(String));
			} else assert.equal(await request.text(), "");

			return current.result === null ? new Response(null, { status: 204 }) : Response.json(current.result);
		} catch (error) { dispatchFailure = error; throw error; }
	};

	try {
		await withMcpClient(undefined, async (client) => {
			const tools = await client.listTools();
			assert.match(tools.tools[0].description, /twilio\.request/);

			for (const query of ["twilio", "send SMS", "message delivery status", "voice calls", "phone numbers"]) {
				const result = await client.callTool({ name: "code", arguments: { code: `async () => await codemode.search(${JSON.stringify(query)})` } });
				assert.ok(result.structuredContent.result.results.some((match) => match.path === "twilio.request"), query);
			}

			const docs = await client.callTool({ name: "code", arguments: { code: "async () => await codemode.describe('twilio.request')" } });
			assert.match(JSON.stringify(docs), /form parameters|form body fields/);
			assert.doesNotMatch(JSON.stringify(docs), /test-twilio-api-secret/);

			for (current of cases) {
				const result = await client.callTool({ name: "code", arguments: { code: `async () => await twilio.request(${JSON.stringify(current.options)})` } });

				if (dispatchFailure) throw dispatchFailure;
				assert.equal(result.isError, undefined, JSON.stringify(result));
				assert.deepEqual(result.structuredContent.result, current.result);
				assert.deepEqual(JSON.parse(result.content[0].text), current.result);
				assert.ok(!JSON.stringify(result).includes(TEST_SECRETS.TWILIO_API_KEY_SID));
				assert.ok(!JSON.stringify(result).includes(TEST_SECRETS.TWILIO_API_KEY_SECRET));
			}
		});
		assert.equal(calls, cases.length);
	} finally { globalThis.fetch = originalFetch; }
});

test("Twilio rejects credential overrides, account escapes, unsupported paths and invalid form parameters before dispatch", async () => {
	const originalFetch = globalThis.fetch;
	let calls = 0;
	globalThis.fetch = async (input, init) => {
		if (!new URL(new Request(input, init).url).hostname.endsWith("twilio.com")) return originalFetch(input, init);
		calls++;

		return Response.json({ unexpected: true });
	};

	const base = { method: "GET", path: "/2010-04-01/Accounts/{AccountSid}/Messages.json" };

	try {
		await withMcpClient(undefined, async (client) => {
			for (const override of [
				{ method: "OPTIONS" }, { accountSid: "other" }, { headers: { Authorization: "Basic override" } }, { url: "https://evil.example/" },
				{ path: "https://api.twilio.com/2010-04-01/Accounts/other/Messages.json" },
				{ path: "/v1/Services" }, { path: "/2010-04-01/Accounts.json" },
				{ path: `/2010-04-01/Accounts/AC${"c".repeat(32)}/Messages.json` },
				{ path: "/2010-04-01/Accounts/{AccountSid}/../../Accounts.json" },
				{ path: "/2010-04-01/Accounts/{AccountSid}/%2e%2e/Accounts.json" },
				{ path: "/2010-04-01/Accounts/{AccountSid}/Messages.json?PageSize=1.json" },
				{ path: "/2010-04-01/Accounts/{AccountSid}/Messages.xml" },
				...['Keys', 'SigningKeys', 'Tokens'].map((name) => ({ method: "POST", path: `/2010-04-01/Accounts/{AccountSid}/${name}.json`, body: {} })),
				{ path: "/2010-04-01/Accounts/{AccountSid}/%4beys.json" },
				{ path: "/2010-04-01/Accounts/{AccountSid}/%254beys.json" },
				{ path: "/2010-04-01/Accounts/{AccountSid}//Messages.json" },
				{ query: { api_key: "override" } }, { query: { PageSize: {} } }, { body: { To: "no GET body" } },
				{ method: "POST", body: [] }, { method: "POST", body: { Nested: { unsafe: true } } },
				{ method: "POST", body: { Invalid: null } },
			]) {
				const result = await client.callTool({ name: "code", arguments: { code: `async () => await twilio.request(${JSON.stringify({ ...base, ...override })})` } });
				assert.equal(result.isError, true, JSON.stringify(override));
			}
		});
		assert.equal(calls, 0);
	} finally { globalThis.fetch = originalFetch; }
});

test("Twilio shares read retries and redaction without replaying sends or other writes", async () => {
	const originalFetch = globalThis.fetch;
	const encoded = Buffer.from(`${TEST_SECRETS.TWILIO_API_KEY_SID}:${TEST_SECRETS.TWILIO_API_KEY_SECRET}`).toString("base64");
	let calls = 0;
	let status = 503;
	let recover = false;
	globalThis.fetch = async (input, init) => {
		if (new URL(new Request(input, init).url).hostname !== "api.twilio.com") return originalFetch(input, init);
		calls++;

		if (recover && calls > 1) return Response.json({ messages: [] });

		return Response.json({ code: 21614, message: `Provider error ${TEST_SECRETS.TWILIO_API_KEY_SID} ${TEST_SECRETS.TWILIO_API_KEY_SECRET} ${encoded}` },
			{ status, headers: { "Retry-After": "0", "X-Request-Id": `request-${TEST_SECRETS.TWILIO_API_KEY_SECRET}` } });
	};

	try {
		await withMcpClient(undefined, async (client) => {
			const invoke = (method) => client.callTool({ name: "code", arguments: { code: `async () => await twilio.request({ method: '${method}', path: '/2010-04-01/Accounts/{AccountSid}/Messages.json' ${method === "POST" ? ", body: { To: '+15555550123', From: '+15555550456', Body: 'fixture' }" : ""} })` } });
			recover = true;
			assert.equal((await invoke("GET")).isError, undefined);
			assert.equal(calls, 2);
			recover = false;

			for (status of [400, 401, 403, 429, 503]) {
				calls = 0;
				const result = await invoke("POST");
				assert.equal(result.isError, true);
				assert.equal(calls, 1);
				assert.match(result.content[0].text, new RegExp(`HTTP ${status}`));
				assert.match(result.content[0].text, /safe_to_replay=false/);
				assert.match(result.content[0].text, status === 503 ? /outcome=unknown/ : /outcome=rejected/);

				if (status !== 401) assert.match(result.content[0].text, /code=21614/);

				for (const secret of [TEST_SECRETS.TWILIO_API_KEY_SID, TEST_SECRETS.TWILIO_API_KEY_SECRET, encoded])
					assert.ok(!JSON.stringify(result).includes(secret));
			}
		});
	} finally { globalThis.fetch = originalFetch; }
});

test("Twilio does not follow redirects or replay successful writes with unsupported response formats", async () => {
	const originalFetch = globalThis.fetch;
	let mode = "redirect";
	let calls = 0;
	globalThis.fetch = async (input, init) => {
		const url = new URL(new Request(input, init).url);

		if (!["api.twilio.com", "evil.example"].includes(url.hostname)) return originalFetch(input, init);
		assert.equal(url.hostname, "api.twilio.com");
		calls++;

		if (mode === "network") throw new Error("private network error test-twilio-api-secret");

		return mode === "redirect" ? new Response(null, { status: 302, headers: { Location: "https://evil.example/" } })
			: new Response("private-media-data", { headers: { "Content-Type": "image/jpeg; filename=private-header" } });
	};

	try {
		await withMcpClient(undefined, async (client) => {
			for (mode of ["redirect", "media", "network"]) {
				calls = 0;
				const result = await client.callTool({ name: "code", arguments: { code: "async () => await twilio.request({ method: 'POST', path: '/2010-04-01/Accounts/{AccountSid}/Messages.json', body: {} })" } });
				assert.equal(result.isError, true);
				assert.equal(calls, 1);
				assert.match(result.content[0].text, mode === "redirect" ? /HTTP 302/ : mode === "media" ? /unsupported_response.*outcome=succeeded/ : /outcome=unknown/);
				assert.doesNotMatch(JSON.stringify(result), /private-media-data|private-header|private network error|test-twilio-api-secret/);
			}
		});
	} finally { globalThis.fetch = originalFetch; }
});

test("Twilio fails clearly without dispatch when credentials are missing or malformed", async () => {
	const originalFetch = globalThis.fetch;
	let calls = 0;
	globalThis.fetch = async (input, init) => {
		if (new URL(new Request(input, init).url).hostname !== "api.twilio.com") return originalFetch(input, init);
		calls++;

		return Response.json({ unexpected: true });
	};

	try {
		for (const secrets of [{ TWILIO_ACCOUNT_SID: "" }, { TWILIO_API_KEY_SID: "" }, { TWILIO_API_KEY_SECRET: "" },
			{ TWILIO_ACCOUNT_SID: "private-invalid-account" }, { TWILIO_API_KEY_SID: "private-invalid-key" }]) {
			const harness = createConciergeHarness(true, secrets);
			const client = new Client({ name: "twilio-config-test", version: "1" });

			try {
				const listener = await harness.listen();
				await client.connect(new StreamableHTTPClientTransport(new URL("/debug/mcp", listener.url)));
				const result = await client.callTool({ name: "code", arguments: { code: "async () => await twilio.request({ method: 'GET', path: '/2010-04-01/Accounts/{AccountSid}/Messages.json' })" } });
				assert.equal(result.isError, true);
				assert.match(result.content[0].text, /must be configured|valid Account SID and API Key SID/);
				assert.doesNotMatch(JSON.stringify(result), /private-invalid|test-twilio-api-secret/);
			} finally { await client.close(); await harness.close(); }
		}

		assert.equal(calls, 0);
	} finally { globalThis.fetch = originalFetch; }
});

test("discovers UniFi and preserves native Site Manager, Network and Protect requests and responses", async () => {
	const originalFetch = globalThis.fetch;
	const requests = [];
	const consoleId = "test-console:123";
	const network = `/v1/connector/consoles/${encodeURIComponent(consoleId)}/proxy/network/integration/v1/`;
	const protect = `/v1/connector/consoles/${encodeURIComponent(consoleId)}/proxy/protect/integration/v1/`;
	const hosts = { data: [{ id: consoleId, owner: true, reportedState: { name: "Test console" } }], nextToken: "next-page:123", httpStatusCode: 200 };
	const sites = { data: [{ id: "local-site-id", name: "Test site" }], count: 1, offset: 0, limit: 1, totalCount: 2 };
	const cameras = [{ id: "camera-id", state: "CONNECTED" }];
	globalThis.fetch = async (input, init) => {
		const request = new Request(input, init);
		const url = new URL(request.url);

		if (url.hostname !== "api.ui.com") return originalFetch(input, init);
		requests.push(request);

		if (request.method === "DELETE") return new Response(null, { status: 204 });

		return Response.json(url.pathname === "/v1/hosts" ? hosts : url.pathname.startsWith(protect) ? cameras : sites);
	};

	try {
		await withMcpClient(undefined, async (client) => {
			const tools = await client.listTools();
			assert.match(tools.tools[0].description, /unifi\.request/);

			for (const query of ["unifi", "wifi clients", "camera NVR status", "console discovery", "camera snapshot"]) {
				const result = await client.callTool({ name: "code", arguments: { code: `async () => await codemode.search(${JSON.stringify(query)})` } });
				assert.equal(result.isError, undefined);
				assert.ok(result.structuredContent.result.results.some((match) => match.path === "unifi.request"), query);
			}

			const docs = await client.callTool({ name: "code", arguments: { code: "async () => await codemode.describe('unifi.request')" } });
			assert.equal(docs.isError, undefined);
			assert.match(docs.structuredContent.result.types, /GET.*POST.*PUT.*PATCH.*DELETE/s);
			assert.match(docs.structuredContent.result.description, /\/v1\/hosts/);
			assert.match(docs.structuredContent.result.description, /siteId/);

			for (const [options, expectedPayload] of [
				[{ method: "GET", path: "/v1/hosts", query: { pageSize: 1, nextToken: "next-page:123" } }, hosts],
				[{ method: "GET", path: "/v1/devices", query: { hostIds: [consoleId, "another-console"] } }, sites],
				[{ method: "GET", path: `${network}sites`, query: { offset: 0, limit: 1 } }, sites],
				[{ method: "GET", path: `${network}sites/local-site-id/clients`, query: { filter: "name.like('Test')" } }, sites],
				[{ method: "GET", path: `${protect}cameras` }, cameras],
				[{ method: "POST", path: `${network}sites/local-site-id/networks`, body: { name: "Test network" } }, sites],
				[{ method: "PUT", path: `${network}sites/local-site-id/networks/network-id`, body: { name: "Updated network" } }, sites],
				[{ method: "PATCH", path: `${protect}cameras/camera-id`, body: { name: "Updated camera" } }, cameras],
				[{ method: "DELETE", path: `${network}sites/local-site-id/networks/network-id` }, null],
			]) {
				const result = await client.callTool({ name: "code", arguments: { code: `async () => await unifi.request(${JSON.stringify(options)})` } });
				assert.equal(result.isError, undefined, JSON.stringify(options));
				assert.deepEqual(result.structuredContent.result, expectedPayload);
				const request = requests.at(-1);
				const expectedUrl = new URL(options.path, "https://api.ui.com");

				for (const [key, value] of Object.entries(options.query ?? {})) for (const item of Array.isArray(value) ? value : [value]) expectedUrl.searchParams.append(key, String(item));
				assert.equal(request.url, expectedUrl.href);
				assert.equal(request.method, options.method);
				assert.equal(request.headers.get("X-API-Key"), TEST_SECRETS.UNIFI_API_KEY);
				assert.equal(request.headers.get("Accept"), "application/json, image/jpeg");
				assert.equal(request.headers.has("Authorization"), false);
				assert.equal(request.headers.has("X-Goog-Api-Key"), false);

				if (options.body) {
					assert.equal(request.headers.get("Content-Type"), "application/json");
					assert.deepEqual(await request.json(), options.body);
				}

				assert.doesNotMatch(JSON.stringify(result), /test-unifi-api-key|test-maps-api-key|test-google-workspace-token/);
			}
		});
	} finally { globalThis.fetch = originalFetch; }
});

test("rejects invalid UniFi inputs, credential overrides, and unsupported proxy boundaries before dispatch", async () => {
	const originalFetch = globalThis.fetch;
	let calls = 0;
	globalThis.fetch = async (input, init) => {
		const request = new Request(input, init);

		if (new URL(request.url).hostname !== "api.ui.com") return originalFetch(input, init);
		calls++;

		return Response.json({});
	};

	try {
		await withMcpClient(undefined, async (client) => {
			for (const override of [
				{ method: "TRACE" }, { body: {} }, { extra: true }, { headers: { "X-API-Key": "caller-key" } },
				{ query: { api_key: "caller-key" } }, { query: { access_token: "caller-token" } }, { query: { nested: {} } },
				{ path: "https://evil.example/v1/hosts" }, { path: "https://api.ui.com/v1/hosts" },
				{ path: "/v1/../token" }, { path: "/v1/%2e%2e/token" }, { path: "/v1/hosts?key=caller-key" }, { path: "/v1/hosts#fragment" },
				{ path: "/v1/connector" }, { path: "/v1/connector/consoles/id/proxy/drive/api/v2/files" },
				{ path: "/v1/connector/consoles/id/proxy/network/api/s/default/stat/sta" },
				{ path: "/v1/connector/consoles/id/proxy/users/api/v1/users" },
				{ path: "/v1/connector/consoles/id/proxy/protect/integration/v1/../../api/bootstrap" },
				{ path: "/v1/connector/consoles/id/proxy/network/integration/v1/%252e%252e/api" },
				{ path: "/v1/connector/consoles/id%2Fproxy/proxy/network/integration/v1/sites" },
				{ path: "/v1/connector//consoles/id/proxy/network/integration/v1/sites" },
				{ path: "/v1/connector/consoles/id/proxy/network/integration/v1/".replace("/proxy/", "/proxy\\") },
			]) {
				const options = { method: "GET", path: "/v1/hosts", ...override };
				const result = await client.callTool({ name: "code", arguments: { code: `async () => await unifi.request(${JSON.stringify(options)})` } });
				assert.equal(result.isError, true, JSON.stringify(override));
			}
		});
		assert.equal(calls, 0);
	} finally { globalThis.fetch = originalFetch; }
});

test("UniFi reuses shared read retries, preserves unknown writes, and redacts provider errors", async () => {
	const originalFetch = globalThis.fetch;
	let calls = 0;
	let status = 503;
	let recover = true;
	globalThis.fetch = async (input, init) => {
		const request = new Request(input, init);

		if (new URL(request.url).hostname !== "api.ui.com") return originalFetch(input, init);
		calls++;

		if (recover && calls > 1) return Response.json({ data: [], nextToken: "next-page" });

		return Response.json({ code: "provider_error", message: `private-body ${TEST_SECRETS.UNIFI_API_KEY}`, traceId: `trace-${TEST_SECRETS.UNIFI_API_KEY}` }, { status, headers: { "Retry-After": "0" } });
	};

	try {
		await withMcpClient(undefined, async (client) => {
			const invoke = (method = "GET") => client.callTool({ name: "code", arguments: {
				code: `async () => await unifi.request({ method: '${method}', path: '/v1/connector/consoles/id/proxy/protect/integration/v1/cameras/camera-id', ${method === "GET" ? "" : "body: { name: 'Updated camera' }"} })`,
			} });

			assert.deepEqual((await invoke()).structuredContent.result, { data: [], nextToken: "next-page" });
			assert.equal(calls, 2);
			calls = 0; status = 408;
			assert.equal((await invoke()).isError, undefined);
			assert.equal(calls, 2, "A proxy timeout may be retried for a read.");

			for (const mutationStatus of [408, 429, 503]) {
				calls = 0; status = mutationStatus;
				const result = await invoke("PATCH");
				assert.equal(result.isError, true);
				assert.equal(calls, 1);
				assert.match(result.content[0].text, /safe_to_replay=false/);
				assert.match(result.content[0].text, mutationStatus === 429 ? /outcome=rejected/ : /outcome=unknown/);
				assert.doesNotMatch(JSON.stringify(result), /test-unifi-api-key/);
			}

			for (const authStatus of [401, 403]) {
				calls = 0; status = authStatus; recover = false;
				const result = await invoke();
				assert.equal(result.isError, true);
				assert.equal(calls, 1);
				assert.doesNotMatch(JSON.stringify(result), /private-body|test-unifi-api-key/);
			}
		});
	} finally { globalThis.fetch = originalFetch; }
});

test("UniFi rejects redirects and unsupported media without exposing response bodies", async () => {
	const originalFetch = globalThis.fetch;
	let mode = "redirect";
	let calls = 0;
	globalThis.fetch = async (input, init) => {
		const request = new Request(input, init);

		if (!["api.ui.com", "evil.example"].includes(new URL(request.url).hostname)) return originalFetch(input, init);
		assert.equal(new URL(request.url).hostname, "api.ui.com", "API credentials must never follow a redirect.");
		calls++;

		return mode === "redirect" ? new Response(null, { status: 302, headers: { Location: "https://evil.example/" } })
			: new Response("private-image-data", { headers: { "Content-Type": "video/mp4" } });
	};

	try {
		await withMcpClient(undefined, async (client) => {
			for (const currentMode of ["redirect", "media"]) {
				mode = currentMode; calls = 0;

				const result = await client.callTool({ name: "code", arguments: {
					code: "async () => await unifi.request({ method: 'GET', path: '/v1/connector/consoles/id/proxy/protect/integration/v1/cameras/camera-id/snapshot' })",
				} });

				assert.equal(result.isError, true);
				assert.equal(calls, 1);
				assert.match(result.content[0].text, currentMode === "media"
					? /unsupported response format \(video\/mp4\).*application\/json.*image\/jpeg.*unsupported_response/
					: /HTTP 302/);
				assert.doesNotMatch(JSON.stringify(result), /private-image-data|test-unifi-api-key/);
			}
		});
	} finally { globalThis.fetch = originalFetch; }
});

test("delivers returned Protect JPEG snapshots as native MCP images with compact JSON references", async (t) => {
	const originalFetch = globalThis.fetch;
	let calls = 0;
	let body = JPEG;
	let contentType = "IMAGE/JPEG; filename=private-camera-name.jpg";
	let status = 200;
	const snapshot = "unifi.request({ method: 'GET', path: '/v1/connector/consoles/id/proxy/protect/integration/v1/cameras/camera-id/snapshot', query: { highQuality: false } })";
	globalThis.fetch = async (input, init) => {
		const request = new Request(input, init);

		if (new URL(request.url).hostname !== "api.ui.com") return originalFetch(input, init);
		calls++;
		assert.equal(request.headers.get("X-API-Key"), TEST_SECRETS.UNIFI_API_KEY);
		assert.equal(request.headers.get("Accept"), "application/json, image/jpeg");

		return new Response(body, { status, headers: { "Content-Type": contentType } });
	};

	try {
		await withMcpClient(undefined, async (client) => {
			const invoke = (code) => client.callTool({ name: "code", arguments: { code } });
			const metadata = (index, byteLength = body.length) => ({ type: "image", mimeType: "image/jpeg", byteLength, contentIndex: index });
			await t.test("delivers a direct image without base64 in text or structured content", async () => {
				const result = await invoke(`async () => await ${snapshot}`);
				assert.equal(result.isError, undefined);
				assert.deepEqual(result.structuredContent.result, metadata(1));
				assert.deepEqual(JSON.parse(result.content[0].text), metadata(1));
				assert.deepEqual(result.content[1], { type: "image", mimeType: "image/jpeg", data: JPEG_BASE64 });
				assert.doesNotMatch(JSON.stringify(result.structuredContent), /\/9j|private-camera-name|test-unifi-api-key/);
			});
			await t.test("delivers images over the modern MCP protocol too", async () => {
				await withMcpClient({ versionNegotiation: { mode: { pin: MODERN_PROTOCOL_VERSION } } }, async (modern) => {
					const result = await modern.callTool({ name: "code", arguments: { code: `async () => await ${snapshot}` } });
					assert.equal(result.isError, undefined);
					assert.equal(result.content[1].data, JPEG_BASE64);
					assert.deepEqual(result.structuredContent.result, metadata(1));
				});
			});
			await t.test("preserves nested multiple images alongside JSON and only delivers returned images", async () => {
				const result = await invoke(`async () => { const snapshot = await ${snapshot}; return { camera: { id: 'camera-id' }, snapshots: [snapshot, { detail: snapshot }] }; }`);
				assert.deepEqual(result.structuredContent.result, { camera: { id: "camera-id" }, snapshots: [metadata(1), { detail: metadata(2) }] });
				assert.deepEqual(JSON.parse(result.content[0].text), result.structuredContent.result);
				assert.equal(result.content.length, 3);
				assert.equal(result.content[2].data, JPEG_BASE64);
				const ignored = await invoke(`async () => { await ${snapshot}; return { inspected: true }; }`);
				assert.deepEqual(ignored.structuredContent.result, { inspected: true });
				assert.equal(ignored.content.length, 1);
			});
			await t.test("does not truncate image bytes when truncating large JSON output", async () => {
				body = Buffer.concat([JPEG, Buffer.alloc(900_000)]);
				assert.ok(body.toString("base64").length > 1_000_000, "Exercise Code Mode's durable value limit.");
				const result = await invoke(`async () => ({ snapshot: await ${snapshot}, note: 'x'.repeat(200000) })`);
				assert.equal(result.isError, undefined);
				assert.match(result.content[0].text, /--- TRUNCATED ---/);
				assert.deepEqual(result.structuredContent.result.snapshot, metadata(1));
				assert.deepEqual(Buffer.from(result.content[1].data, "base64"), body);
				assert.deepEqual(JSON.parse(result.content[0].text), result.structuredContent.result);
				body = JPEG;
			});
			await t.test("keeps image bytes out of Code Mode and rejects references from another invocation", async () => {
				const reference = await invoke(`async () => { const image = await ${snapshot}; return { keys: Object.keys(image).sort(), imageId: image.imageId, byteLength: image.byteLength }; }`);
				assert.deepEqual(reference.structuredContent.result.keys, ["byteLength", "imageId", "mimeType", "type"]);
				assert.equal(reference.content.length, 1);
				const saved = reference.structuredContent.result;
				const stale = await invoke(`async () => ({ type: 'image', mimeType: 'image/jpeg', imageId: '${saved.imageId}', byteLength: ${saved.byteLength} })`);
				assert.equal(stale.isError, true);
				assert.match(stale.content[0].text, /unchanged image references from this invocation/);
				assert.equal(stale.content.length, 1);
			});
			await t.test("bounds image count and aggregate size without delivering partial or truncated images", async () => {
				for (const [bytes, code] of [
					[JPEG, `async () => { const image = await ${snapshot}; return Array(5).fill(image); }`],
					[Buffer.concat([JPEG, Buffer.alloc(2097153 - JPEG.length)]), `async () => { const image = await ${snapshot}; return [image, image]; }`],
				]) {
					body = bytes;
					const before = calls;
					const result = await invoke(code);
					assert.equal(result.isError, true);
					assert.equal(calls, before + 1);
					assert.match(result.content[0].text, /at most 4 images totaling 4 MiB.*do not replay writes/);
					assert.equal(result.content.length, 1);
					assert.equal(result.structuredContent, undefined);
				}

				body = JPEG;
			});
			await t.test("bounds retained bytes and image count even when fetched images are not returned", async () => {
				for (const [bytes, count, dispatched] of [
					[JPEG, 5, 5],
					[Buffer.concat([JPEG, Buffer.alloc(2097153 - JPEG.length)]), 2, 2],
				]) {
					body = bytes;
					const before = calls;
					const result = await invoke(`async () => { for (let i=0; i<${count}; i++) await ${snapshot}; return true; }`);
					assert.equal(result.isError, true);
					assert.equal(calls, before + dispatched);
					assert.match(result.content[0].text, /Retrieve at most 4 images totaling 4 MiB.*do not replay writes/);
					assert.equal(result.content.length, 1);
				}

				body = JPEG;
			});
			await t.test("rejects invalid JPEG, unsupported images and video, and preserves non-JSON HTTP failures", async () => {
				for (const [type, bytes, httpStatus, expected] of [
					["image/jpeg", Buffer.from("private-not-image"), 200, /invalid JPEG.*invalid_response/],
					["image/png", JPEG, 200, /unsupported_response/],
					["video/mp4", JPEG, 200, /unsupported_response/],
					["image/svg+xml", Buffer.from("private-svg"), 200, /unsupported_response/],
					["image/jpeg", JPEG, 403, /HTTP 403.*permission/],
					["image/jpeg", Buffer.alloc(4 * 1024 * 1024 + 1), 200, /response_too_large/],
				]) {
					contentType = type; body = bytes; status = httpStatus;
					const before = calls;
					const result = await invoke(`async () => await ${snapshot}`);
					assert.equal(result.isError, true);
					assert.equal(calls, before + 1);
					assert.match(result.content[0].text, expected);
					assert.doesNotMatch(JSON.stringify(result), /private-not-image|private-svg|test-unifi-api-key/);
					assert.ok(result.content.every((entry) => entry.type === "text"));
				}
			});
		});
	} finally { globalThis.fetch = originalFetch; }
});

test("UniFi fails clearly before dispatch when its API key is missing", async () => {
	const harness = createConciergeHarness(true, { UNIFI_API_KEY: "" });
	const originalFetch = globalThis.fetch;
	let calls = 0;
	globalThis.fetch = async (input, init) => {
		if (new URL(new Request(input, init).url).hostname === "api.ui.com") {
			calls++;

			return Response.json({});
		}

		return originalFetch(input, init);
	};

	try {
		await harness.listen();
		await withMcpClient(undefined, async (client) => {
			const result = await client.callTool({ name: "code", arguments: { code: "async () => await unifi.request({ method: 'GET', path: '/v1/hosts' })" } });
			assert.equal(result.isError, true);
			assert.match(result.content[0].text, /UNIFI_API_KEY is not configured/);
		}, harness);
		assert.equal(calls, 0);
	} finally {
		globalThis.fetch = originalFetch;
		await harness.close();
	}
});

test("calls Maps with native query/body, server-owned credentials, and unchanged JSON", async () => {
	const originalFetch = globalThis.fetch;
	const requests = [];

	const payload = { places: [{ id: "test-place", displayName: { text: "Test cafe" }, rating: 4.8, userRatingCount: 120,
		attributions: [{ provider: "Google Maps" }], reviews: [{ authorAttribution: { displayName: "Test reviewer" } }] }] };

	globalThis.fetch = async (input, init) => {
		const request = new Request(input, init);

		if (new URL(request.url).hostname !== "places.googleapis.com") return originalFetch(input, init);
		requests.push(request);

		return Response.json(payload);
	};

	try {
		await withMcpClient(undefined, async (client) => {
			const tools = await client.listTools();
			assert.match(tools.tools[0].description, /maps\.request/);

			const docs = await client.callTool({ name: "code", arguments: {
				code: "async () => ({ search: await codemode.search('business ratings'), docs: await codemode.describe('maps.request') })",
			} });

			assert.ok(docs.structuredContent.result.search.results.some((match) => match.path === "maps.request"));
			assert.match(docs.structuredContent.result.docs.types, /places/);

			for (const options of [
				{ service: "places", method: "POST", path: "/v1/places:searchText", query: { fields: "places.id,places.rating,places.userRatingCount" }, body: { textQuery: "coffee shops in Brooklyn", pageSize: 1 } },
				{ service: "places", method: "GET", path: "/v1/places/test-place", query: { "$fields": "id,rating,userRatingCount", languageCode: "en" } },
				{ service: "places", method: "GET", path: "/v1/places/test-place/photos/photo/media", query: { skipHttpRedirect: true, maxWidthPx: 100 } },
			]) {
				const result = await client.callTool({ name: "code", arguments: { code: `async () => await maps.request(${JSON.stringify(options)})` } });
				assert.equal(result.isError, undefined);
				assert.deepEqual(result.structuredContent.result, payload);
				const request = requests.at(-1);
				const expected = new URL(options.path, "https://places.googleapis.com");
				expected.search = new URLSearchParams(options.query).toString();
				assert.equal(request.url, expected.href);
				assert.equal(request.method, options.method);
				assert.equal(request.headers.get("X-Goog-Api-Key"), TEST_SECRETS.GOOGLE_MAPS_API_KEY);
				assert.equal(request.headers.has("Authorization"), false);

				if (options.body) assert.deepEqual(await request.json(), options.body);
			}
		});
	} finally { globalThis.fetch = originalFetch; }
});

test("calls Routes and route matrices with native bodies, masks, and unchanged per-element outcomes", async () => {
	const originalFetch = globalThis.fetch;
	const requests = [];
	const routes = { routes: [{ distanceMeters: 1200, duration: "600s", polyline: { encodedPolyline: "test-polyline" } }] };

	const matrix = [
		{ originIndex: 0, destinationIndex: 0, status: {}, condition: "ROUTE_EXISTS", distanceMeters: 1200, duration: "600s" },
		{ originIndex: 0, destinationIndex: 1, status: { code: 5, message: "No route found" }, condition: "ROUTE_NOT_FOUND" },
	];

	globalThis.fetch = async (input, init) => {
		const request = new Request(input, init);

		if (new URL(request.url).hostname !== "routes.googleapis.com") return originalFetch(input, init);
		requests.push(request);

		return Response.json(new URL(request.url).pathname === "/directions/v2:computeRoutes" ? routes : matrix);
	};

	try {
		await withMcpClient(undefined, async (client) => {
			const docs = await client.callTool({ name: "code", arguments: {
				code: "async () => ({ search: await codemode.search('travel time'), docs: await codemode.describe('maps.request') })",
			} });

			assert.ok(docs.structuredContent.result.search.results.some((match) => match.path === "maps.request"));
			assert.match(docs.structuredContent.result.docs.types, /routes/);
			assert.match(docs.structuredContent.result.docs.types, /computeRouteMatrix/);
			const origin = { location: { latLng: { latitude: 40.7484, longitude: -73.9857 } } };
			const destination = { address: "Grand Central Terminal, New York" };

			for (const [options, payload] of [
				[{ service: "routes", method: "POST", path: "/directions/v2:computeRoutes", query: { fields: "routes.distanceMeters,routes.duration,routes.polyline.encodedPolyline" }, body: { origin, destination, travelMode: "WALK" } }, routes],
				[{ service: "routes", method: "POST", path: "/distanceMatrix/v2:computeRouteMatrix", query: { "$fields": "originIndex,destinationIndex,status,condition,distanceMeters,duration" }, body: { origins: [{ waypoint: origin }], destinations: [{ waypoint: destination }, { waypoint: { address: "Test destination" } }], travelMode: "DRIVE" } }, matrix],
			]) {
				const result = await client.callTool({ name: "code", arguments: { code: `async () => await maps.request(${JSON.stringify(options)})` } });
				assert.equal(result.isError, undefined);
				assert.deepEqual(result.structuredContent.result, payload);
				const request = requests.at(-1);
				const expected = new URL(options.path, "https://routes.googleapis.com");
				expected.search = new URLSearchParams(options.query).toString();
				assert.equal(request.url, expected.href);
				assert.equal(request.method, "POST");
				assert.equal(request.headers.get("X-Goog-Api-Key"), TEST_SECRETS.GOOGLE_MAPS_API_KEY);
				assert.equal(request.headers.has("Authorization"), false);
				assert.deepEqual(await request.json(), options.body);
			}
		});
	} finally { globalThis.fetch = originalFetch; }
});

test("rejects Maps credential overrides, invalid inputs, and endpoint escapes before dispatch", async () => {
	const originalFetch = globalThis.fetch;
	let calls = 0;
	globalThis.fetch = async (input, init) => {
		const request = new Request(input, init);

		if (!["places.googleapis.com", "routes.googleapis.com"].includes(new URL(request.url).hostname)) return originalFetch(input, init);
		calls++;

		return Response.json({});
	};

	try {
		await withMcpClient(undefined, async (client) => {
			const base = { service: "places", method: "GET", path: "/v1/places/test-place" };

			for (const override of [
				{ service: "gmail" }, { method: "DELETE" }, { body: {} }, { fields: ["rating"] },
				{ headers: { "X-Goog-Api-Key": "caller-key" } }, { query: { key: "caller-key" } },
				{ query: { access_token: "caller-token" } }, { query: { nested: {} } },
				{ path: "https://evil.example/v1/places/test-place" }, { path: "/v1/../token" },
				{ path: "/v1/%2e%2e/token" }, { path: "/v1/places/test-place?key=caller-key" },
			]) {
				const result = await client.callTool({ name: "code", arguments: { code: `async () => await maps.request(${JSON.stringify({ ...base, ...override })})` } });
				assert.equal(result.isError, true, JSON.stringify(override));
			}

			const route = { service: "routes", method: "POST", path: "/directions/v2:computeRoutes", body: {} };

			for (const override of [
				{ method: "GET" }, { method: "DELETE" }, { service: "places" },
				{ path: "/v1/places:searchText" }, { path: "/directions/v2:futureOperation" },
				{ path: "https://evil.example/directions/v2:computeRoutes" },
				{ path: "/directions/v2:computeRoutes?key=caller-key" },
				{ headers: { "X-Goog-Api-Key": "caller-key" } }, { query: { key: "caller-key" } },
			]) {
				const result = await client.callTool({ name: "code", arguments: { code: `async () => await maps.request(${JSON.stringify({ ...route, ...override })})` } });
				assert.equal(result.isError, true, JSON.stringify(override));
			}
		});
		assert.equal(calls, 0);
	} finally { globalThis.fetch = originalFetch; }
});

test("Maps retries known read-only POSTs, never assumes arbitrary POSTs are safe, and redacts API keys", async () => {
	const originalFetch = globalThis.fetch;
	let calls = 0;
	let status = 503;
	let recover = true;
	globalThis.fetch = async (input, init) => {
		const request = new Request(input, init);

		if (new URL(request.url).hostname !== "places.googleapis.com") return originalFetch(input, init);
		calls++;

		if (recover && calls > 1) return Response.json({ places: [] });

		return Response.json({ error: { status: "UNAVAILABLE", message: `Rejected ${TEST_SECRETS.GOOGLE_MAPS_API_KEY}` } }, { status });
	};

	try {
		await withMcpClient(undefined, async (client) => {
			const invoke = (path) => client.callTool({ name: "code", arguments: { code: `async () => await maps.request({ service: 'places', method: 'POST', path: '${path}', query: { fields: 'places.id' }, body: {} })` } });
			assert.equal((await invoke("/v1/places:searchText")).isError, undefined);
			assert.equal(calls, 2);
			calls = 0;
			const unknown = await invoke("/v1/places:futureOperation");
			assert.equal(unknown.isError, true);
			assert.equal(calls, 1);
			assert.match(unknown.content[0].text, /safe_to_replay=false/);
			assert.doesNotMatch(JSON.stringify(unknown), /test-maps-api-key/);
			calls = 0; status = 403; recover = false;
			const denied = await invoke("/v1/places:searchText");
			assert.equal(denied.isError, true);
			assert.equal(calls, 1);
			assert.doesNotMatch(JSON.stringify(denied), /test-maps-api-key|Rejected/);
		});
	} finally { globalThis.fetch = originalFetch; }
});

test("Routes retries both read-only POST endpoints and redacts denied requests", async () => {
	const originalFetch = globalThis.fetch;
	let calls = 0;
	let denied = false;
	globalThis.fetch = async (input, init) => {
		const request = new Request(input, init);

		if (new URL(request.url).hostname !== "routes.googleapis.com") return originalFetch(input, init);
		calls++;

		if (!denied && calls > 1) return Response.json({});

		return Response.json({ error: { status: denied ? "PERMISSION_DENIED" : "UNAVAILABLE", message: `Rejected ${TEST_SECRETS.GOOGLE_MAPS_API_KEY}` } }, { status: denied ? 403 : 503 });
	};

	try {
		await withMcpClient(undefined, async (client) => {
			for (const path of ["/directions/v2:computeRoutes", "/distanceMatrix/v2:computeRouteMatrix"]) {
				calls = 0;
				const result = await client.callTool({ name: "code", arguments: { code: `async () => await maps.request({ service: 'routes', method: 'POST', path: '${path}', query: { fields: 'status' }, body: {} })` } });
				assert.equal(result.isError, undefined);
				assert.equal(calls, 2);
			}

			calls = 0; denied = true;
			const result = await client.callTool({ name: "code", arguments: { code: "async () => await maps.request({ service: 'routes', method: 'POST', path: '/directions/v2:computeRoutes', body: {} })" } });
			assert.equal(result.isError, true);
			assert.equal(calls, 1);
			assert.doesNotMatch(JSON.stringify(result), /test-maps-api-key|Rejected/);
		});
	} finally { globalThis.fetch = originalFetch; }
});

test("Maps fails clearly when its API key is missing", async () => {
	const harness = createConciergeHarness(true, { GOOGLE_MAPS_API_KEY: "" });

	try {
		await harness.listen();
		await withMcpClient(undefined, async (client) => {
			const result = await client.callTool({ name: "code", arguments: {
				code: "async () => await maps.request({ service: 'places', method: 'GET', path: '/v1/places/test-place', query: { fields: 'id' } })",
			} });

			assert.equal(result.isError, true);
			assert.match(result.content[0].text, /GOOGLE_MAPS_API_KEY is not configured/);
		}, harness);
	} finally { await harness.close(); }
});

test("schema-parsed error metadata preserves HTTP failures and valid sibling fields", async () => {
	const originalFetch = globalThis.fetch;
	const harness = createConciergeHarness(true);

	const cases = [
		{ code: "async () => await twilio.request({ method: 'POST', path: '/2010-04-01/Accounts/{AccountSid}/Messages.json', body: {} })",
			status: 400, payload: { message: { private: "private-metadata" }, code: 21614 }, expected: /code=21614/ },
		{ code: "async () => await unifi.request({ method: 'POST', path: '/v1/hosts', body: {} })",
			status: 400, payload: { message: ["private-metadata"], code: "native-unifi-code", traceId: {} }, expected: /code=native-unifi-code/ },
		{ code: "async () => await maps.request({ service: 'places', method: 'POST', path: '/v1/places:searchText', body: {} })",
			status: 400, payload: { error: { message: 12, status: "INVALID_ARGUMENT", future: "private-metadata" } }, expected: /code=INVALID_ARGUMENT/ },
		{ code: "async () => await exa.request({ method: 'POST', path: '/agent/runs', body: {} })",
			status: 400, payload: { error: { message: ["private-metadata"], code: "native-exa-code" }, tag: 12, requestId: [] }, expected: /code=native-exa-code/ },
		{ code: "async () => await google.request({ service: 'gmail', method: 'POST', path: '/gmail/v1/users/me/messages/send', body: {} })",
			status: 403, payload: { error: { message: false, errors: [false, { reason: 12 }, { reason: "rateLimitExceeded" }] } }, expected: /rate_limited/ },
	];

	let current;
	let calls = 0;
	globalThis.fetch = async (input, init) => {
		const url = new URL(new Request(input, init).url);

		if (url.hostname === "oauth2.googleapis.com") return Response.json({ access_token: "test-error-metadata-token", expires_in: 3600 });

		if (!["api.twilio.com", "api.ui.com", "places.googleapis.com", "api.exa.ai", "gmail.googleapis.com"].includes(url.hostname)) return originalFetch(input, init);
		calls++;

		return Response.json(current.payload, { status: current.status });
	};

	try {
		await harness.listen();
		await withMcpClient(undefined, async (client) => {
			for (current of cases) {
				calls = 0;
				const result = await client.callTool({ name: "code", arguments: { code: current.code } });
				assert.equal(result.isError, true);
				assert.equal(calls, 1);
				assert.match(result.content[0].text, new RegExp(`HTTP ${current.status}`));
				assert.match(result.content[0].text, current.expected);
				assert.doesNotMatch(JSON.stringify(result), /private-metadata|test-error-metadata-token|invalid_response|ZodError/);
			}
		}, harness);
	} finally { globalThis.fetch = originalFetch; await harness.close(); }
});

test("calls Google Workspace through signed JWTs, fixed delegation, and a private token cache", async (t) => {
	const originalFetch = globalThis.fetch;
	const requests = [];
	let rejectToken = false;
	let expiresIn = 3600;
	let apiStatus = 200;
	let apiPayload = { emailAddress: "joe@j1.io" };
	globalThis.fetch = async (input, init) => {
		const request = new Request(input, init);
		const url = new URL(request.url);
		assert.ok(!["sts.mtls.googleapis.com", "iamcredentials.googleapis.com"].includes(url.hostname), "Legacy federation must not be used.");

		if (!["oauth2.googleapis.com", "gmail.googleapis.com"].includes(url.hostname)) {
			return originalFetch(input, init);
		}

		requests.push(request.clone());

		if (url.hostname === "oauth2.googleapis.com") {
			const body = new URLSearchParams(await request.text());
			assert.equal(body.get("grant_type"), "urn:ietf:params:oauth:grant-type:jwt-bearer");
			const [header, payload, signature] = body.get("assertion").split(".");
			assert.deepEqual(JSON.parse(Buffer.from(header, "base64url")), { alg: "RS256", typ: "JWT", kid: "test-google-key-id" });
			assert.ok(verify("RSA-SHA256", Buffer.from(`${header}.${payload}`), GOOGLE_KEYS.publicKey, Buffer.from(signature, "base64url")));
			const jwt = JSON.parse(Buffer.from(payload, "base64url"));
			assert.equal(jwt.sub, "joe@j1.io");
			assert.equal(jwt.iss, "concierge@j1-concierge.iam.gserviceaccount.com");
			assert.equal(jwt.aud, "https://oauth2.googleapis.com/token");
			assert.equal(jwt.exp - jwt.iat, 600);
			assert.deepEqual(jwt.scope.split(" ").sort(), [
				"https://mail.google.com/",
				"https://www.googleapis.com/auth/gmail.settings.basic",
				"https://www.googleapis.com/auth/gmail.settings.sharing",
			].sort());

			if (rejectToken) return Response.json({ error_description: "do-not-expose-workspace-secret" }, { status: 400 });

			return Response.json({ access_token: "test-google-workspace-token", expires_in: expiresIn });
		}

		assert.equal(request.headers.get("Authorization"), "Bearer test-google-workspace-token");

		if (apiStatus === 204) return new Response(null, { status: 204 });

		if (apiStatus === 302) return new Response(null, { status: 302, headers: { Location: "https://evil.example/steal" } });

		return Response.json(apiPayload, { status: apiStatus, headers: { "Retry-After": "0" } });
	};

	const count = (hostname) => requests.filter((request) => new URL(request.url).hostname === hostname).length;

	const call = (client, options) => client.callTool({ name: "code", arguments: {
		code: `async () => await google.request(${JSON.stringify(options)})`,
	} });

	const profile = { service: "gmail", method: "GET", path: "/gmail/v1/users/me/profile" };

	try {
		await withMcpClient(undefined, async (client) => {
			await t.test("rejects invalid services, external URLs, other users, traversal, and caller-selected credentials before authentication", async () => {
				for (const options of [
					{ ...profile, service: "drive" },
					{ ...profile, method: "TRACE" },
					{ ...profile, path: "https://evil.example/steal" },
					{ ...profile, path: "/gmail/v1/users/other@example.com/profile" },
					{ ...profile, path: "/gmail/v1/users/me/../../other/profile" },
					{ ...profile, path: "/gmail/v1/users/me/%2e%2e/%2e%2e/other/profile" },
					{ ...profile, path: "/gmail/v1/users/me/profile?access_token=evil" },
					{ ...profile, query: { access_token: "evil" } },
					{ ...profile, query: { bad: { nested: true } } },
					{ ...profile, sub: "other@example.com" },
					{ ...profile, body: {} },
				]) {
					const result = await call(client, options);
					assert.equal(result.isError, true, JSON.stringify(options));
				}

				assert.equal(requests.length, 0);
			});
			await t.test("deduplicates concurrent authentication and hides all credentials from MCP results", async () => {
				const result = await client.callTool({ name: "code", arguments: {
					code: `async () => await Promise.all([google.request(${JSON.stringify(profile)}), google.request(${JSON.stringify(profile)}), google.request(${JSON.stringify(profile)})])`,
				} });

				assert.equal(result.isError, undefined);
				assert.deepEqual(result.structuredContent.result, Array(3).fill({ emailAddress: "joe@j1.io" }));
				assert.equal(count("oauth2.googleapis.com"), 1);
				assert.doesNotMatch(JSON.stringify(result), /test-google-workspace-token/);
				assert.ok(!JSON.stringify(result).includes(GOOGLE_CREDENTIALS.private_key));
				assert.doesNotMatch(JSON.stringify(result), /PRIVATE KEY/);
			});
			await t.test("supports query arrays, JSON writes, settings, and empty delete responses without reauth", async () => {
				await call(client, { ...profile, path: "/gmail/v1/users/me/messages", query: { labelIds: ["INBOX", "UNREAD"], maxResults: 2 } });
				const list = requests.at(-1);
				assert.deepEqual(new URL(list.url).searchParams.getAll("labelIds"), ["INBOX", "UNREAD"]);
				assert.equal(new URL(list.url).searchParams.get("maxResults"), "2");
				assert.equal(list.method, "GET");
				const body = { name: "Test" };
				await call(client, { service: "gmail", method: "POST", path: "/gmail/v1/users/me/labels", body });
				assert.equal(requests.at(-1).method, "POST");
				assert.deepEqual(await requests.at(-1).json(), body);
				await call(client, { service: "gmail", method: "PUT", path: "/gmail/v1/users/me/settings/language", body: { displayLanguage: "en" } });
				assert.equal(requests.at(-1).method, "PUT");
				apiStatus = 204;
				assert.deepEqual((await call(client, { service: "gmail", method: "DELETE", path: "/gmail/v1/users/me/labels/test" })).structuredContent, { result: null });
				apiStatus = 200;
				assert.equal(count("oauth2.googleapis.com"), 1);
			});
			await t.test("invalidates rejected tokens without replaying mutations, follows no redirects, and surfaces API errors", async () => {
				apiStatus = 401;
				apiPayload = { error: { message: "Rejected test-google-workspace-token" } };
				const before = count("gmail.googleapis.com");
				const result = await call(client, { service: "gmail", method: "POST", path: "/gmail/v1/users/me/messages/send", body: { raw: "test" } });
				assert.equal(result.isError, true);
				assert.match(result.content[0].text, /HTTP 401/);
				assert.doesNotMatch(result.content[0].text, /test-google-workspace-token/);
				assert.equal(count("gmail.googleapis.com"), before + 1);
				apiStatus = 302;
				assert.equal((await call(client, profile)).isError, true);
				assert.equal(count("oauth2.googleapis.com"), 2);
				apiStatus = 429;
				apiPayload = { error: { message: "Rate limit exceeded" } };
				assert.match((await call(client, profile)).content[0].text, /Rate limit exceeded.*Retry-After: 0s/);
				apiStatus = 401;
				await call(client, profile);
				apiStatus = 200;
			});
			await t.test("recovers after authentication failures without leaking upstream error bodies", async () => {
				rejectToken = true;
				const result = await call(client, profile);
				assert.equal(result.isError, true);
				assert.match(result.content[0].text, /Google .*returned HTTP/);
				assert.doesNotMatch(JSON.stringify(result), /do-not-expose/);
				rejectToken = false;
				expiresIn = 60;
				assert.match((await call(client, profile)).content[0].text, /invalid access token/);
				expiresIn = 61;
				assert.equal((await call(client, profile)).isError, undefined);
				const before = count("oauth2.googleapis.com");
				await new Promise((resolve) => setTimeout(resolve, 1100));
				expiresIn = 3600;
				assert.equal((await call(client, profile)).isError, undefined);
				assert.equal(count("oauth2.googleapis.com"), before + 1);
			});
		});
		await t.test("rejects invalid or mismatched service-account credentials without leaking them", async () => {
			const before = requests.length;

			for (const credentials of [
				'{"private_key":"do-not-expose-key"',
				JSON.stringify({ ...GOOGLE_CREDENTIALS, client_email: "other@example.com" }),
				JSON.stringify({ ...GOOGLE_CREDENTIALS, private_key: "do-not-expose-key" }),
				JSON.stringify({ ...GOOGLE_CREDENTIALS, private_key_id: "" }),
			]) {
				const server = createConciergeHarness(true, { GOOGLE_SERVICE_ACCOUNT_JSON: credentials });

				try {
					await server.listen();
					await withMcpClient(undefined, async (client) => {
						const result = await call(client, profile);
						assert.equal(result.isError, true);
						assert.match(result.content[0].text, /valid key for the Concierge service account/);
						assert.doesNotMatch(JSON.stringify(result), /do-not-expose|PRIVATE KEY/);
					}, server);
				} finally {
					await server.close();
				}
			}

			assert.equal(requests.length, before);
		});
	} finally {
		globalThis.fetch = originalFetch;
	}
});

test("shares bounded reliability behavior across connector operations", async (t) => {
	const run = async options => (await debugServer.getWorker("reliability-test").fetch("https://test.example/", {
		method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(options),
	})).json();

	await t.test("keeps registered namespaces, metadata and discovery hints aligned", async () => {
		const catalog = await run({ action: "catalog" });
		assert.equal(new Set(catalog.map(({ id }) => id)).size, catalog.length);
		assert.equal(new Set(catalog.map(({ label }) => label)).size, catalog.length);
		await withMcpClient(undefined, async (client) => {
			const { tools: [tool] } = await client.listTools();

			for (const entry of catalog) {
				assert.ok(entry.hint.length > 0);
				assert.ok(tool.description.includes(entry.hint));
				const result = await client.callTool({ name: "code", arguments: { code: `async () => await codemode.describe(${JSON.stringify(entry.id)})` } });
				assert.equal(result.isError, undefined);
				assert.match(JSON.stringify(result.structuredContent.result), new RegExp(entry.id));
			}
		});
	});
	await t.test("derives tool schemas and parses arguments before invoking the typed handler", async () => {
		const valid = await run({ action: "tool", args: { name: "  example  " } });
		assert.deepEqual(valid.result, { name: "example", count: 2, executionId: "test-execution" });
		assert.equal(valid.inputSchema.properties.name.type, "string");
		assert.equal(valid.inputSchema.properties.count.default, 2);
		assert.equal(valid.inputSchema.additionalProperties, false);

		for (const args of [null, {}, { name: 1 }, { name: "test", extra: true }]) {
			assert.ok((await run({ action: "tool", args })).error);
		}
	});
	await t.test("shares request validation without widening provider contracts", async () => {
		const contract = { methods: ["GET", "POST"], pathPrefix: "/api/" };
		const args = { method: "GET", path: "/api/items", query: { flag: true, count: 2, name: "test" } };
		const parsed = await run({ action: "inputs", contract, args });
		assert.deepEqual(parsed.result, args);
		assert.equal(parsed.inputSchema.$schema, "http://json-schema.org/draft-07/schema#");
		assert.equal(parsed.inputSchema.additionalProperties, false);
		assert.deepEqual(parsed.inputSchema.required, ["method", "path"]);
		assert.deepEqual(parsed.inputSchema.properties.method.enum, contract.methods);
		assert.ok(new RegExp(parsed.inputSchema.properties.path.pattern).test(args.path));
		assert.ok(!new RegExp(parsed.inputSchema.properties.path.pattern).test("/outside"));
		assert.equal(parsed.inputSchema.properties.query.additionalProperties.anyOf.some((entry) => entry.type === "array"), false);
		const write = { ...args, method: "POST", body: { name: "test" } };
		assert.deepEqual((await run({ action: "inputs", contract, args: write })).result, write);

		for (const invalid of [null, [], "request", { ...args, extra: true }, { ...args, method: "PUT" }, { ...args, method: 1 }, { ...args, path: "/outside" }, { ...args, path: null }, { ...args, query: null }, { ...args, query: [] }, { ...args, query: { nested: {} } }, { ...args, query: { values: ["one"] } }, { ...args, body: null }]) {
			assert.ok((await run({ action: "inputs", contract, args: invalid })).error, JSON.stringify(invalid));
		}

		const googleContract = { ...contract, queryArrays: true, extraKeys: ["service"] };
		const googleArgs = { ...args, service: "gmail", query: { values: ["one", 2, true] } };
		assert.deepEqual((await run({ action: "inputs", contract: googleContract, args: googleArgs })).result, googleArgs);
		const googleSchema = (await run({ action: "inputs", contract: googleContract, args: googleArgs })).inputSchema;
		assert.ok(googleSchema.required.includes("service"));
		assert.ok(googleSchema.properties.query.additionalProperties.anyOf.some((entry) => entry.type === "array"));
		assert.ok((await run({ action: "inputs", contract: googleContract, args: { ...googleArgs, query: { nested: [["one"]] } } })).error);
	});
	await t.test("parses Retry-After seconds and HTTP dates, rejecting malformed values", async () => {
		assert.deepEqual(await run({ action: "retry-after", values: [null, "", "5", "0", "-1", "Infinity", "garbage", "Thu, 01 Jan 1970 00:00:05 GMT"] }), [null, null, 5000, 0, null, null, null, 5000]);
	});
	await t.test("validates API URL boundaries and serializes finite scalar queries", async () => {
		const allowed = await run({ action: "url", path: "/api/items", query: { tag: ["one", "two"], enabled: true } });
		assert.equal(allowed.url, "https://example.com/api/items?tag=one&tag=two&enabled=true");

		for (const path of ["https://evil.example/api/items", "/api/../../outside", "/api/%2e%2e/outside", "/api/a%2fb", "/api/items?token=evil", "/api/items#fragment", "/api/\\evil"]) {
			assert.ok((await run({ action: "url", path })).error, path);
		}

		assert.ok((await run({ action: "url", path: "/api/items", query: { access_token: "evil" } })).error);
	});
	await t.test("bounds retries and does not replay ambiguous writes", async () => {
		const failure = { category: "http", message: "API returned HTTP 503.", retryable: true, status: 503 };
		const read = await run({ failure });
		assert.equal(read.attempts, 3);
		assert.match(read.results[0].error, /attempts=3/);
		const write = await run({ failure, readOnly: false });
		assert.equal(write.attempts, 1);
		assert.match(write.results[0].error, /safe_to_replay=false.*outcome=unknown.*verify external state/);
		const network = await run({ failureRaw: true, readOnly: false });
		assert.equal(network.attempts, 1);
		assert.equal(network.results[0].details.category, "network");
		assert.doesNotMatch(network.results[0].error, /fixture-secret/);
		const idempotent = await run({ failure, readOnly: false, replaySafe: true });
		assert.equal(idempotent.attempts, 3);
		const uncertain = await run({ failure, readOnly: false, replaySafe: true, failPreparationAfterFirst: true });
		assert.equal(uncertain.attempts, 2);
		assert.equal(uncertain.results[0].details.outcome, "unknown", "Later preparation failure must not erase an earlier uncertain write.");
		const rejected = await run({ failure: { ...failure, category: "rate_limited", safeToReplay: true, outcome: "rejected" }, readOnly: false });
		assert.equal(rejected.attempts, 3);
		assert.equal(rejected.results[0].details.outcome, "rejected");
	});
	await t.test("surfaces long Retry-After without retrying ahead of the provider", async () => {
		const result = await run({ count: 2, limits: { concurrency: 1 }, failure: { category: "rate_limited", message: "Wait.", retryable: true, retryAfterMs: 60_000 } });
		assert.equal(result.attempts, 1);
		assert.match(result.results[0].error, /Retry-After: 60s/);
		assert.equal(result.results[1].details.outcome, "not_started");
	});
	await t.test("honors Retry-After and shares cooldowns with queued provider operations", async () => {
		const result = await run({ count: 2, delayMs: 1, limits: { concurrency: 1 }, failuresBeforeSuccess: 1, failure: { category: "rate_limited", message: "Wait.", retryable: true, retryAfterMs: 40 } });
		assert.equal(result.attempts, 3);
		assert.ok(result.dispatchTimes[1] - result.dispatchTimes[0] >= 40);
		assert.ok(result.dispatchTimes[2] - result.dispatchTimes[0] >= 40);
		assert.ok(result.results.every(result => result.result === "ok"));
	});
	await t.test("limits concurrency, bounds the queue, and retains permits for non-cancellable work", async () => {
		const parallel = await run({ count: 8, delayMs: 15, limits: { concurrency: 2 } });
		assert.equal(parallel.peak, 2);
		assert.equal(parallel.attempts, 8);
		assert.ok(parallel.results.every(result => result.result === "ok"));
		const bounded = await run({ count: 5, delayMs: 40, limits: { concurrency: 1, maxQueued: 1 } });
		assert.equal(bounded.attempts, 2);
		assert.equal(bounded.results.filter(result => result.details?.category === "busy").length, 3);
		const expired = await run({ count: 3, delayMs: 100, readOnly: false, limits: { timeoutMs: 25, concurrency: 1 } });
		assert.equal(expired.attempts, 1);
		assert.equal(expired.peak, 1);
		assert.equal(expired.active, 0);
		assert.equal(expired.results[0].details.outcome, "unknown");
		assert.equal(expired.results[1].details.outcome, "not_started");
	});
	await t.test("deadlines cover body reading and size limits cancel streams", async () => {
		const slow = await run({ action: "body", readOnly: false, limits: { timeoutMs: 25 } });
		assert.equal(slow.cancelled, true);
		assert.equal(slow.results[0].details.category, "timeout");
		assert.equal(slow.results[0].details.outcome, "succeeded");
		const large = await run({ action: "body", body: "x".repeat(100), limits: { maxResponseBytes: 16 } });
		assert.equal(large.cancelled, true);
		assert.equal(large.results[0].details.category, "response_too_large");
	});
	await t.test("derives request headers and advertised MIME support from the response registry", async () => {
		const originalFetch = globalThis.fetch;

		try {
			for (const format of ["json", "json-or-text", "json-or-image"]) {
				const formats = await run({ action: "formats", format });
				assert.deepEqual(formats.types, [
					{ kind: "json", mimeType: "application/json" },
					{ kind: "image", mimeType: "image/jpeg" },
				]);
				const supported = formats.types.filter((type) => type.kind === "json" || format === "json-or-image");
				assert.equal(formats.accept, supported.map((type) => type.mimeType).join(", "));

				for (const type of supported) assert.ok(formats.description.includes(type.mimeType));

				if (format !== "json-or-image") assert.ok(!formats.description.includes("image/jpeg"));
				globalThis.fetch = async (input, init) => {
					const request = new Request(input, init);
					assert.equal(request.headers.get("Accept"), formats.accept);

					return Response.json({ unchanged: true });
				};

				assert.deepEqual((await run({ action: "request", format })).result, { unchanged: true });
			}
		} finally { globalThis.fetch = originalFetch; }
	});
	await t.test("rejects unsupported formats without buffering media or replaying successful writes", async () => {
		const formats = await run({ action: "formats" });

		for (const contentType of ["IMAGE/JPEG; filename=private-header", "image/png", "text/html", "application/octet-stream", "not a media type private-header"]) {
			const result = await run({ action: "body", readOnly: false, body: "private-response-body", headers: { "Content-Type": contentType } });
			assert.equal(result.cancelled, true);
			assert.equal(result.attempts, 1);
			assert.equal(result.results[0].details.category, "unsupported_response");
			assert.equal(result.results[0].details.outcome, "succeeded");
			assert.ok(result.results[0].error.includes(`this connector accepts ${formats.description}.`));
			assert.match(result.results[0].error, /retryable=false.*safe_to_replay=false.*outcome=succeeded/);
			assert.doesNotMatch(JSON.stringify(result), /private-response-body|private-header|invalid JSON/);

			if (contentType.startsWith("IMAGE")) assert.match(result.results[0].error, /\(image\/jpeg\)/);
		}
	});
	await t.test("preserves JSON media types, missing headers, empty successes, and malformed JSON errors", async () => {
		for (const contentType of [undefined, "application/json; charset=utf-8", "application/problem+json", "Application/Vnd.Example+Json"]) {
			const result = await run({ action: "body", closeBody: true, body: '{"unchanged":true}', headers: contentType ? { "Content-Type": contentType } : {} });
			assert.deepEqual(result.results[0].result, { unchanged: true });
		}

		const empty = await run({ action: "body", closeBody: true, body: "", headers: { "Content-Type": "text/plain" } });
		assert.equal(empty.results[0].result, null);
		const malformed = await run({ action: "body", closeBody: true, body: "private-response-body", headers: { "Content-Type": "application/json" } });
		assert.equal(malformed.results[0].details.category, "invalid_response");
		assert.match(malformed.results[0].error, /invalid JSON/);
		assert.doesNotMatch(malformed.results[0].error, /private-response-body/);
		const text = await run({ action: "body", closeBody: true, body: "plain text", format: "json-or-text", headers: { "Content-Type": "text/plain" } });
		assert.equal(text.results[0].result, "plain text");
	});
	await t.test("image response mode preserves shared byte limits, cancellation, deadlines, and JSON", async () => {
		const options = { action: "body", format: "json-or-image", bodyBase64: JPEG_BASE64, headers: { "Content-Type": "image/jpeg" } };
		const image = await run({ ...options, closeBody: true });
		assert.equal(image.results[0].result.mimeType, "image/jpeg");
		assert.deepEqual(Buffer.from(Object.values(image.results[0].result.data)), JPEG);
		const parameterized = await run({ ...options, closeBody: true, headers: { "Content-Type": "IMAGE/JPEG; filename=private-header" } });
		assert.equal(parameterized.results[0].result.mimeType, "image/jpeg");
		assert.deepEqual(Buffer.from(Object.values(parameterized.results[0].result.data)), JPEG);
		const large = await run({ ...options, limits: { maxResponseBytes: JPEG.length - 1 } });
		assert.equal(large.cancelled, true);
		assert.equal(large.results[0].details.category, "response_too_large");
		const slow = await run({ ...options, readOnly: false, limits: { timeoutMs: 25 } });
		assert.equal(slow.cancelled, true);
		assert.equal(slow.results[0].details.category, "timeout");
		assert.equal(slow.results[0].details.outcome, "succeeded");
		const video = await run({ ...options, headers: { "Content-Type": "video/mp4" } });
		assert.equal(video.cancelled, true);
		assert.equal(video.results[0].details.category, "unsupported_response");
		const formats = await run({ action: "formats", format: "json-or-image" });
		assert.ok(video.results[0].error.includes(`this connector accepts ${formats.description}.`));
		const json = await run({ action: "body", format: "json-or-image", closeBody: true, body: '{"native":true}', headers: { "Content-Type": "application/json" } });
		assert.deepEqual(json.results[0].result, { native: true });
	});
	await t.test("shares provider-bound REST encoding, URL restrictions and read-only POST policies", async () => {
		const originalFetch = globalThis.fetch;
		const requests = [];
		let status = 200;
		globalThis.fetch = async (input, init) => {
			const request = new Request(input, init);
			requests.push({ method: request.method, url: request.url, headers: Object.fromEntries(request.headers), body: await request.text() });

			return Response.json({ native: true }, { status });
		};

		try {
			const args = { method: "POST", path: "/api/items", query: { tag: ["one", "two"] }, body: { native: [1, true] } };
			assert.deepEqual((await run({ action: "rest", args })).result, { native: true });
			assert.equal(requests[0].url, "https://reliability.example/api/items?tag=one&tag=two");
			assert.equal(requests[0].headers["content-type"], "application/json");
			assert.equal(requests[0].headers["x-test-credential"], "fixture-secret");
			assert.deepEqual(JSON.parse(requests[0].body), args.body);
			await run({ action: "rest", form: true, args: { ...args, body: { To: ["first", "second"], Enabled: true } } });
			assert.equal(requests[1].headers["content-type"], "application/x-www-form-urlencoded");
			assert.deepEqual([...new URLSearchParams(requests[1].body)], [["To", "first"], ["To", "second"], ["Enabled", "true"]]);

			for (const path of ["https://evil.example/api/items", "/api/a%252fb", "/api//items", "/api/blocked"]) {
				assert.ok((await run({ action: "rest", args: { method: "GET", path } })).error);
			}

			assert.equal(requests.length, 2);
			status = 503;

			for (const [method, path, expected] of [["GET", "/api/items", 3], ["POST", "/api/search", 3], ["POST", "/api/items", 1], ["DELETE", "/api/search", 1]]) {
				requests.length = 0;
				const failed = await run({ action: "rest", args: { method, path, readOnly: true } });
				assert.ok(failed.error);
				assert.equal(requests.length, expected);
			}
		} finally {
			globalThis.fetch = originalFetch;
		}
	});
	await t.test("pairs refreshed authentication with generic error redaction on every attempt", async () => {
		const originalFetch = globalThis.fetch;
		const attempts = [];
		globalThis.fetch = async (input, init) => {
			const request = new Request(input, init);
			const credential = request.headers.get("X-Test-Credential");
			attempts.push(credential);

			return Response.json({ message: `Failed ${credential}`, code: credential }, { status: 503, headers: { "X-Request-Id": credential } });
		};

		try {
			const failed = await run({ action: "request", rotateAuth: true });
			assert.deepEqual(attempts, ["fixture-secret-1", "fixture-secret-2", "fixture-secret-3"]);
			assert.match(failed.error, /\[redacted\]/);
			assert.doesNotMatch(JSON.stringify(failed), /fixture-secret/);
		} finally {
			globalThis.fetch = originalFetch;
		}
	});
	await t.test("HTTP requests include preparation in deadlines and redact credentials", async () => {
		const originalFetch = globalThis.fetch;
		let requests = 0;
		let mode = "failure";
		globalThis.fetch = async (input, init) => {
			const request = new Request(input, init);

			if (request.url !== "https://reliability.example/api") return originalFetch(input, init);
			requests++;

			if (mode === "redirect") return new Response(null, { status: 302, headers: { Location: "https://evil.example/credentials" } });

			if (mode === "invalid") return new Response("not-json", { headers: { "Content-Type": "application/json" } });

			if (mode === "html-failure") return new Response("private-error-body fixture-secret", { status: 503, headers: { "Content-Type": "text/html" } });

			if (mode === "media") return new Response("private-image-body", { headers: { "Content-Type": "image/png; filename=fixture-secret" } });

			if (mode === "authentication") return Response.json({ message: "fixture-secret private-token-body" }, { status: 401 });

			if (mode === "success") return Response.json({ unchanged: true });

			return Response.json({ message: "Rejected fixture-secret", code: "fixture-secret" }, { status: 503, headers: { "X-Request-Id": "request-123" } });
		};

		try {
			const failed = await run({ action: "request" });
			assert.equal(requests, 3);
			assert.match(failed.error, /\[redacted\]/);
			assert.doesNotMatch(failed.error, /fixture-secret/);
			assert.equal(failed.details.requestId, "request-123");
			mode = "redirect";
			const redirect = await run({ action: "request", readOnly: false });
			assert.equal(requests, 4);
			assert.equal(redirect.details.status, 302);
			mode = "invalid";
			const malformedWrite = await run({ action: "request", readOnly: false });
			assert.equal(malformedWrite.details.category, "invalid_response");
			assert.equal(malformedWrite.details.outcome, "succeeded");
			mode = "media";
			const beforeMedia = requests;
			const mediaWrite = await run({ action: "request", readOnly: false });
			assert.equal(requests, beforeMedia + 1);
			assert.equal(mediaWrite.details.category, "unsupported_response");
			assert.equal(mediaWrite.details.outcome, "succeeded");
			assert.doesNotMatch(mediaWrite.error, /private-image-body|fixture-secret/);
			mode = "html-failure";
			const beforeHtml = requests;
			const htmlFailure = await run({ action: "request" });
			assert.equal(requests, beforeHtml + 3);
			assert.equal(htmlFailure.details.category, "http");
			assert.equal(htmlFailure.details.status, 503);
			assert.doesNotMatch(htmlFailure.error, /private-error-body|fixture-secret|unsupported_response|invalid JSON/);
			mode = "authentication";
			const auth = await run({ action: "request" });
			assert.equal(auth.details.category, "authentication");
			assert.doesNotMatch(auth.error, /fixture-secret|private-token-body/);
			const before = requests;
			const deadline = await run({ action: "request", readOnly: false, prepareMs: 100, limits: { timeoutMs: 25 } });
			assert.equal(deadline.details.category, "timeout");
			assert.equal(deadline.details.outcome, "not_started");
			await new Promise(resolve => setTimeout(resolve, 120));
			assert.equal(requests, before, "Expired preparation must not dispatch a late write.");
			mode = "success";
			assert.deepEqual((await run({ action: "request" })).result, { unchanged: true });
			const beforeLogFailure = requests;
			assert.deepEqual((await run({ action: "request", loggingFailure: true })).result, { unchanged: true });
			assert.equal(requests, beforeLogFailure + 1);
			mode = "failure";
			const failedWrite = await run({ action: "request", readOnly: false, loggingFailure: true });
			assert.equal(requests, beforeLogFailure + 2);
			assert.equal(failedWrite.details.status, 503);
			assert.equal(failedWrite.details.outcome, "unknown");
		} finally { globalThis.fetch = originalFetch; }
	});
});

test("applies shared reliability to real MCP connector calls without replaying Code Mode", async (t) => {
	const originalFetch = globalThis.fetch;
	let mode = "retry";
	let calls = 0;
	let writes = 0;
	let active = 0;
	let peak = 0;
	let googleCalls = 0;
	let authCalls = 0;
	globalThis.fetch = async (input, init) => {
		const request = new Request(input, init);
		const host = new URL(request.url).hostname;

		if (host === "oauth2.googleapis.com") {
			authCalls++;

			if (mode === "google-auth-failure") return Response.json({ error_description: "private signed assertion must not escape" }, { status: 503 });

			return Response.json({ access_token: "test-google-workspace-token", expires_in: 3600 });
		}

		if (host !== "gmail.googleapis.com") return originalFetch(input, init);
		googleCalls++;
		assert.equal(request.headers.get("Authorization"), "Bearer test-google-workspace-token");

		if (mode === "google-invalid") return new Response("invalid-json", { headers: { "Content-Type": "application/json" } });

		if (mode === "google-auth-invalidate") return Response.json({ error: { message: "rejected token" } }, { status: 401 });

		if (mode === "google-permission") return Response.json({ error: { message: "private forbidden body", errors: [{ reason: "domainPolicy" }] } }, { status: 403 });

		if (mode === "google-rate-write") return Response.json({ error: { message: "rate limit", errors: [{ reason: "userRateLimitExceeded" }] } }, { status: 403 });

		if (mode === "google-rate" && googleCalls === 1) return Response.json({ error: { errors: [{ reason: "rateLimitExceeded" }] } }, { status: 403 });

		if (mode.startsWith("google-")) return Response.json({ emailAddress: "joe@j1.io" });
		calls++;

		if (mode === "parallel") {
			active++; peak = Math.max(peak, active);
			await new Promise(resolve => setTimeout(resolve, 20));
			active--;

			return Response.json({ ok: true });
		}

		if (request.method === "POST") {
			writes++;

			if (mode === "uncertain-write") return Response.json({ error: { message: "try again" } }, { status: 503 });

			return Response.json({ created: true });
		}

		if (mode === "retry" && calls < 3 || mode === "sequence" && calls === 2) return Response.json({ error: { message: "temporary failure" } }, { status: 503 });

		return Response.json({ ok: true });
	};

	const read = "google.request({ service: 'gmail', method: 'GET', path: '/gmail/v1/users/me/profile' })";
	const write = "google.request({ service: 'gmail', method: 'POST', path: '/gmail/v1/users/me/messages/send', body: { raw: 'test' } })";
	const invoke = (client, code) => client.callTool({ name: "code", arguments: { code } });

	try {
		await withMcpClient(undefined, async client => {
			await t.test("retries reads while preserving successful tool output", async () => {
				assert.deepEqual((await invoke(client, `async () => await ${read}`)).structuredContent, { result: { ok: true } });
				assert.equal(calls, 3);
			});
			await t.test("does not repeat an uncertain write and preserves catchable error guidance", async () => {
				mode = "uncertain-write"; calls = 0; writes = 0;
				const result = await invoke(client, `async () => { try { return await ${write}; } catch (error) { return String(error); } }`);
				assert.equal(writes, 1);
				assert.match(result.structuredContent.result, /safe_to_replay=false.*outcome=unknown.*verify external state/);
			});
			await t.test("distinguishes Gmail 403 rate limits from permissions without replaying writes", async () => {
				const profile = "google.request({ service: 'gmail', method: 'GET', path: '/gmail/v1/users/me/profile' })";
				mode = "google-rate"; googleCalls = 0;
				assert.deepEqual((await invoke(client, `async () => await ${profile}`)).structuredContent, { result: { emailAddress: "joe@j1.io" } });
				assert.equal(googleCalls, 2);
				mode = "google-permission"; googleCalls = 0;
				const permission = await invoke(client, `async () => await ${profile}`);
				assert.equal(permission.isError, true);
				assert.equal(googleCalls, 1);
				assert.match(permission.content[0].text, /permission/);
				assert.doesNotMatch(permission.content[0].text, /private forbidden/);
				mode = "google-rate-write"; googleCalls = 0;
				const limitedWrite = await invoke(client, "async () => await google.request({ service: 'gmail', method: 'POST', path: '/gmail/v1/users/me/messages/send', body: { raw: 'test' } })");
				assert.equal(limitedWrite.isError, true);
				assert.equal(googleCalls, 1);
				assert.match(limitedWrite.content[0].text, /rate_limited.*safe_to_replay=false/);
				mode = "google-invalid"; googleCalls = 0;
				const malformedWrite = await invoke(client, "async () => await google.request({ service: 'gmail', method: 'POST', path: '/gmail/v1/users/me/messages/send', body: { raw: 'test' } })");
				assert.equal(malformedWrite.isError, true);
				assert.equal(googleCalls, 1);
				assert.match(malformedWrite.content[0].text, /invalid_response.*outcome=succeeded/);
			});
			await t.test("retries Browser Run HTTP failures and rejects malformed successful responses", async () => {
				const success = await invoke(client, "async () => await cloudflare.read_webpage_as_markdown({ url: 'https://example.com/reliability-retry' })");
				assert.equal(success.structuredContent.result.markdown, "# Retried 3 times");
				const invalid = await invoke(client, "async () => await cloudflare.read_webpage_as_markdown({ url: 'https://example.com/reliability-invalid' })");
				assert.equal(invalid.isError, true);
				assert.match(invalid.content[0].text, /invalid_response/);
			});
			await t.test("does not multiply authentication retries at the outer API layer", async () => {
				const profile = "google.request({ service: 'gmail', method: 'GET', path: '/gmail/v1/users/me/profile' })";
				mode = "google-auth-invalidate";
				await invoke(client, `async () => await ${profile}`);
				mode = "google-auth-failure"; authCalls = 0; googleCalls = 0;
				const failed = await invoke(client, `async () => await ${profile}`);
				assert.equal(failed.isError, true);
				assert.equal(authCalls, 3);
				assert.equal(googleCalls, 0);
				assert.doesNotMatch(failed.content[0].text, /private signed assertion/);
				mode = "google-auth-recovered";
				assert.deepEqual((await invoke(client, `async () => await ${profile}`)).structuredContent, { result: { emailAddress: "joe@j1.io" } });
			});
			await t.test("retries one failed request rather than repeating earlier side effects", async () => {
				mode = "sequence"; calls = 0; writes = 0;
				assert.deepEqual((await invoke(client, `async () => { await ${write}; return await ${read}; }`)).structuredContent, { result: { ok: true } });
				assert.equal(writes, 1);
				assert.equal(calls, 3);
			});
			await t.test("shares the provider concurrency gate across concurrent MCP calls", async () => {
				mode = "parallel"; calls = 0; peak = 0;
				const code = `async () => await Promise.all(Array.from({ length: 6 }, () => ${read}))`;
				const results = await Promise.all([invoke(client, code), invoke(client, code)]);
				assert.ok(results.every(result => result.isError === undefined));
				assert.equal(calls, 12);
				assert.equal(peak, 4);
			});
		});
	} finally { globalThis.fetch = originalFetch; }
});

function createConciergeHarness(debugEnabled, secrets = {}) {
	return createTestHarness({
		root: ROOT,
		workers: [
			{
				bindingOverrides: { BROWSER: "browser-mock" },
				configPath: "./wrangler.jsonc",
				secrets: { ...TEST_SECRETS, ...secrets },
				vars: { CONCIERGE_DEBUG: String(debugEnabled) },
			},
			{
				config: {
					compatibility_date: "2026-07-15",
					main: "./tests/fixtures/browser-worker.mjs",
					name: "browser-mock",
				},
			},
			{
				config: {
					compatibility_date: "2026-07-15",
					main: "./tests/fixtures/reliability-worker.mjs",
					name: "reliability-test",
					compatibility_flags: ["nodejs_compat"],
				},
			},
			{
				config: {
					compatibility_date: "2026-07-15",
					main: "./tests/fixtures/mcp-worker.mjs",
					name: "mcp-infrastructure-test",
					services: [{ binding: "CONCIERGE", service: "concierge" }],
				},
			},
		],
	});
}

async function withMcpClient(options, run, server = debugServer) {
	const client = new Client(
		{ name: "concierge-integration-test", version: "1.0.0" },
		options,
	);

	const worker = server.getWorker("concierge");

	const transport = new StreamableHTTPClientTransport(debugMcpUrl, {
		fetch: (input, init) => worker.fetch(input, init),
	});

	try {
		await client.connect(transport);

		return await run(client);
	} finally {
		await client.close();
	}
}

function usageEvents(server, prefix = '{"event":"code_') {
	return server.getLogs().flatMap((log) => log.message ?? []).flatMap((message) => {
		const line = z.string().safeParse(message);

		return line.success && line.data.startsWith(prefix) ? [JSON.parse(line.data)] : [];
	});
}

async function waitFor(check, description) {
	const deadline = performance.now() + 5_000;

	for (;;) {
		const result = check();

		if (result !== undefined) return result;
		assert.ok(performance.now() < deadline, `Timed out waiting for ${description}.`);
		await new Promise((resolve) => setTimeout(resolve, 25));
	}
}

function consentForm(html, decision) {
	const match = html.match(/name="handle" value="([^"]+)"/);
	assert.ok(match, "Missing consent handle");

	return new URLSearchParams({ handle: match[1], decision });
}

function responseCookies(response) {
	return response.headers.getSetCookie()
		.filter((cookie) => !/Max-Age=0(?:;|$)/i.test(cookie))
		.map((cookie) => cookie.split(";")[0])
		.join("; ");
}

function mcpInitializeRequest(extraHeaders = {}) {
	return {
		body: JSON.stringify({
			id: 1,
			jsonrpc: "2.0",
			method: "initialize",
			params: {
				capabilities: {},
				clientInfo: { name: "concierge-integration-test", version: "1.0.0" },
				protocolVersion: LEGACY_PROTOCOL_VERSION,
			},
		}),
		headers: {
			Accept: "application/json, text/event-stream",
			"Content-Type": "application/json",
			...extraHeaders,
		},
		method: "POST",
	};
}
