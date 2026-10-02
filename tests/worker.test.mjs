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
const GOOGLE_CREDENTIALS = {
	type: "service_account",
	client_email: "concierge@j1-concierge.iam.gserviceaccount.com",
	private_key_id: "test-google-key-id",
	private_key: GOOGLE_KEYS.privateKey.export({ type: "pkcs8", format: "pem" }),
};
const TEST_SECRETS = {
	ACCESS_AUTHORIZATION_URL: "https://access.example/authorize",
	ACCESS_CLIENT_ID: "test-access-client",
	ACCESS_CLIENT_SECRET: "test-access-secret",
	ACCESS_JWKS_URL: "https://access.example/jwks",
	ACCESS_TOKEN_URL: "https://access.example/token",
	COOKIE_ENCRYPTION_KEY: "0000000000000000000000000000000000000000000000000000000000000000",
	NOTION_TOKEN: "test-notion-token",
	GOOGLE_SERVICE_ACCOUNT_JSON: JSON.stringify(GOOGLE_CREDENTIALS),
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
		email: "test@example.com",
		exp: Math.floor(Date.now() / 1000) + 300,
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
			return Response.json({ access_token: "test-upstream-token", id_token: idToken });
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

test("serves the code tool over the modern MCP protocol", async () => {
	await withMcpClient(
		{
			versionNegotiation: {
				mode: { pin: MODERN_PROTOCOL_VERSION },
			},
		},
		async (client) => {
			assert.equal(client.getNegotiatedProtocolVersion(), MODERN_PROTOCOL_VERSION);
			const { tools } = await client.listTools();
			assert.equal(tools.length, 1);
			const [tool] = tools;
			assert.equal(tool.name, "code");
			assert.match(tool.description ?? "", /codemode\.search.*connector method names/s);
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

		assert.deepEqual(result.structuredContent, {
			result: "# Mock webpage\nURL: https://example.com/test\nWait: networkidle0",
		});
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
		return Response.json(apiPayload, { status: apiStatus, headers: { "Retry-After": "5" } });
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
				assert.match((await call(client, profile)).content[0].text, /Rate limit exceeded.*Retry-After: 5s/);
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
