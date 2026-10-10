import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes, sign, verify } from "node:crypto";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import {
	Client,
	StreamableHTTPClientTransport,
} from "@modelcontextprotocol/client";
import { createTestHarness } from "wrangler";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const MODERN_PROTOCOL_VERSION = "2026-07-28";
const LEGACY_PROTOCOL_VERSION = "2025-11-25";
const GOOGLE_KEYS = generateKeyPairSync("rsa", { modulusLength: 2048 });
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
	NOTION_TOKEN: "test-notion-token",
	GOOGLE_SERVICE_ACCOUNT_JSON: JSON.stringify(GOOGLE_CREDENTIALS),
	GOOGLE_MAPS_API_KEY: "test-maps-api-key",
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

	const resourceResponse = await productionServer.getWorker("concierge").fetch(
		"https://concierge.j1.io/.well-known/oauth-protected-resource/mcp",
	);
	assert.equal(resourceResponse.status, 200);
	const resourceMetadata = await resourceResponse.json();
	assert.equal(resourceMetadata.resource, "https://concierge.j1.io/mcp");
	assert.deepEqual(resourceMetadata.bearer_methods_supported, ["header"]);
});

test("authorizes a CIMD client through Access and refreshes its MCP token", async () => {
	const clientId = "https://client.example/metadata.json";
	const redirectUri = "https://client.example/callback";
	const verifier = randomBytes(32).toString("base64url");
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
			return Response.json({
				client_id: clientId,
				client_name: "Test MCP Client",
				grant_types: ["authorization_code", "refresh_token"],
				redirect_uris: [redirectUri, "https://client.example/other-callback"],
				response_types: ["code"],
				token_endpoint_auth_method: "none",
			});
		}
		if (request.url === TEST_SECRETS.ACCESS_TOKEN_URL) {
			upstreamTokenRequest = new URLSearchParams(await request.text());
			return Response.json({ access_token: "test-upstream-token", token_type: "Bearer", id_token: idToken });
		}
		if (request.url === TEST_SECRETS.ACCESS_JWKS_URL) {
			return Response.json({ keys: [{ ...publicKey.export({ format: "jwk" }), kid: "test-key" }] });
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
		const exchange = await worker.fetch("https://concierge.j1.io/token", {
			method: "POST",
			body: new URLSearchParams({
				client_id: clientId,
				code: clientCallback.searchParams.get("code"),
				code_verifier: verifier,
				grant_type: "authorization_code",
				redirect_uri: redirectUri,
				resource: "https://concierge.j1.io/mcp",
			}),
		});
		assert.equal(exchange.status, 200);
		const tokens = await exchange.json();
		assert.equal(typeof tokens.access_token, "string");
		assert.equal(typeof tokens.refresh_token, "string");
		const refresh = await worker.fetch("https://concierge.j1.io/token", {
			method: "POST",
			body: new URLSearchParams({
				client_id: clientId,
				grant_type: "refresh_token",
				refresh_token: tokens.refresh_token,
			}),
		});
		assert.equal(refresh.status, 200);
		const refreshed = await refresh.json();
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
});

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
	const options = {
		method: "POST", headers: { "Content-Type": "application/json" }, body: "x".repeat(4 * 1024 * 1024 + 1),
	};
	const response = await debugServer.getWorker("concierge").fetch(debugMcpUrl, options);
	assert.equal(response.status, 413);
	assert.equal(response.headers.get("Access-Control-Allow-Origin"), "*");
	assert.doesNotMatch(JSON.stringify(await response.json()), /xxxxx/);
	const unicode = await debugServer.getWorker("concierge").fetch(debugMcpUrl, {
		...options, body: JSON.stringify({ padding: "\u00e9".repeat(2 * 1024 * 1024) }),
	});
	assert.equal(unicode.status, 413, "The body limit counts UTF-8 bytes, not characters.");
	const production = productionServer.getWorker("concierge");
	assert.equal((await production.fetch("https://concierge.j1.io/mcp", options)).status, 401);
	assert.equal((await production.fetch("https://concierge.j1.io/debug/mcp", options)).status, 404);
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
			const { tools } = await client.listTools();
			assert.equal(tools.length, 1);
			const [tool] = tools;
			assert.equal(tool.name, "code");
			assert.match(tool.description ?? "", /codemode\.search.*connector method names/s);
			const connectorSection = (tool.description ?? "").split("## Available connectors\n")[1]?.split("\n## ")[0];
			assert.ok(connectorSection);
			for (const name of ["cloudflare", "notion", "google", "maps"]) {
				assert.match(connectorSection, new RegExp("- `" + name + "`"));
			}
			assert.match(connectorSection, /Routes API/);
			assert.match(tool.description ?? "", /Search first for the task capability/);
			assert.match(tool.description ?? "", /Prefer a purpose-specific API connector/);
			assert.match(tool.description ?? "", /search for `maps directions`/);
			assert.doesNotMatch(tool.description ?? "", /to read reviews from a Google Maps page|Do not search for `Google Maps reviews`/);
			assert.match(tool.description ?? "", /failed code invocation does not undo earlier connector calls/);
			assert.match(tool.description ?? "", /outcome=unknown/);
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
		const { tools } = await client.listTools();
		assert.deepEqual(
			tools.map((tool) => tool.name),
			["code"],
		);

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
			code: "async () => ({ notion: await codemode.describe('notion.request'), google: await codemode.describe('google.request'), browser: await codemode.describe('cloudflare.read_webpage_as_markdown') })",
		} });
		assert.equal(docs.isError, undefined);
		assert.match(JSON.stringify(docs.structuredContent.result.notion), /GET.*POST.*PATCH.*DELETE/s);
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

test("calls Notion with the configured API contract", async () => {
	const originalFetch = globalThis.fetch;
	let notionRequest;
	globalThis.fetch = async (input, init) => {
		const request = new Request(input, init);
		if (request.url.startsWith("https://api.notion.com/")) {
			notionRequest = request;
			return Response.json({ id: "test-user", object: "user" });
		}

		return originalFetch(input, init);
	};

	try {
		await withMcpClient(undefined, async (client) => {
			const result = await client.callTool({
				name: "code",
				arguments: {
					code: "async () => await notion.request({ method: 'GET', path: '/v1/users/me', query: { preview: true } })",
				},
			});

			assert.deepEqual(result.structuredContent, {
				result: { id: "test-user", object: "user" },
			});
		});

		assert.ok(notionRequest);
		assert.equal(notionRequest.method, "GET");
		assert.equal(notionRequest.url, "https://api.notion.com/v1/users/me?preview=true");
		assert.equal(notionRequest.headers.get("Authorization"), "Bearer test-notion-token");
		assert.equal(notionRequest.headers.get("Notion-Version"), "2026-03-11");
	} finally {
		globalThis.fetch = originalFetch;
	}
});

test("rejects invalid Notion and Google request arguments before outbound calls", async () => {
	const originalFetch = globalThis.fetch;
	let outboundCalls = 0;
	globalThis.fetch = async (input, init) => {
		const request = new Request(input, init);
		if (["api.notion.com", "gmail.googleapis.com", "oauth2.googleapis.com"].includes(new URL(request.url).hostname)) {
			outboundCalls++;
			return Response.json({});
		}
		return originalFetch(input, init);
	};
	try {
		await withMcpClient(undefined, async (client) => {
			for (const [connector, base] of [
				["notion", { method: "GET", path: "/v1/users/me" }],
				["google", { service: "gmail", method: "GET", path: "/gmail/v1/users/me/profile" }],
			]) {
				for (const fields of ["query: { value: NaN }", "query: { value: Infinity }", "query: { value: {} }", "body: {}", "extra: true", "method: 'TRACE'"]) {
					const result = await client.callTool({ name: "code", arguments: {
						code: `async () => await ${connector}.request({ ...${JSON.stringify(base)}, ${fields} })`,
					} });
					assert.equal(result.isError, true, `${connector}: ${fields}`);
				}
			}
			const result = await client.callTool({ name: "code", arguments: {
				code: "async () => await notion.request({ method: 'GET', path: '/v1/users/me', query: { values: ['one'] } })",
			} });
			assert.equal(result.isError, true);
		});
		assert.equal(outboundCalls, 0);
	} finally {
		globalThis.fetch = originalFetch;
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
	await t.test("HTTP requests include preparation in deadlines and redact credentials", async () => {
		const originalFetch = globalThis.fetch;
		let requests = 0;
		let mode = "failure";
		globalThis.fetch = async (input, init) => {
			const request = new Request(input, init);
			if (request.url !== "https://reliability.example/api") return originalFetch(input, init);
			requests++;
			if (mode === "redirect") return new Response(null, { status: 302, headers: { Location: "https://evil.example/credentials" } });
			if (mode === "invalid") return new Response("not-json");
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
		if (host === "gmail.googleapis.com") {
			googleCalls++;
			if (mode === "google-invalid") return new Response("invalid-json");
			if (mode === "google-auth-invalidate") return Response.json({ error: { message: "rejected token" } }, { status: 401 });
			if (mode === "google-permission") return Response.json({ error: { message: "private forbidden body", errors: [{ reason: "domainPolicy" }] } }, { status: 403 });
			if (mode === "google-rate-write") return Response.json({ error: { message: "rate limit", errors: [{ reason: "userRateLimitExceeded" }] } }, { status: 403 });
			if (mode === "google-rate" && googleCalls === 1) return Response.json({ error: { errors: [{ reason: "rateLimitExceeded" }] } }, { status: 403 });
			return Response.json({ emailAddress: "joe@j1.io" });
		}
		if (host !== "api.notion.com") return originalFetch(input, init);
		calls++;
		assert.equal(request.headers.get("Authorization"), "Bearer test-notion-token");
		if (mode === "parallel") {
			active++; peak = Math.max(peak, active);
			await new Promise(resolve => setTimeout(resolve, 20));
			active--;
			return Response.json({ ok: true });
		}
		if (request.method === "POST") {
			writes++;
			if (mode === "uncertain-write") return Response.json({ code: "service_unavailable", message: "try again" }, { status: 503 });
			if (mode === "rate-write" && writes === 1) return Response.json({ code: "rate_limited" }, { status: 429, headers: { "Retry-After": "0" } });
			if (mode === "overload-write" && writes === 1) return Response.json({ code: "service_overload" }, { status: 529, headers: { "Retry-After": "0" } });
			return Response.json({ created: true });
		}
		if (mode === "blocked") return Response.json({ message: "private forbidden body", additional_data: { rate_limit_reason: "public_api_request_blocked" } }, { status: 429 });
		if (mode === "retry" && calls < 3 || mode === "sequence" && calls === 2) return Response.json({ code: "service_unavailable", message: "temporary failure" }, { status: 503 });
		return Response.json({ ok: true });
	};
	const read = "notion.request({ method: 'GET', path: '/v1/users/me' })";
	const write = "notion.request({ method: 'POST', path: '/v1/pages', body: { parent: {} } })";
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
			await t.test("retries a Notion-confirmed rate-limit rejection of a write", async () => {
				mode = "rate-write"; calls = 0; writes = 0;
				assert.deepEqual((await invoke(client, `async () => await ${write}`)).structuredContent, { result: { created: true } });
				assert.equal(writes, 2);
			});
			await t.test("does not retry Notion access restrictions or expose forbidden bodies", async () => {
				mode = "blocked"; calls = 0;
				const result = await invoke(client, `async () => await ${read}`);
				assert.equal(result.isError, true);
				assert.equal(calls, 1);
				assert.match(result.content[0].text, /permission/);
				assert.doesNotMatch(result.content[0].text, /private forbidden/);
			});
			await t.test("retries a Notion-confirmed overload rejection of a write", async () => {
				mode = "overload-write"; calls = 0; writes = 0;
				assert.deepEqual((await invoke(client, `async () => await ${write}`)).structuredContent, { result: { created: true } });
				assert.equal(writes, 2);
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
				},
			},
			{
				config: {
					compatibility_date: "2026-07-15",
					main: "./tests/fixtures/mcp-worker.mjs",
					name: "mcp-infrastructure-test",
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
