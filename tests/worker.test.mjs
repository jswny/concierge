import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
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
const TEST_SECRETS = {
	ACCESS_AUTHORIZATION_URL: "https://access.example/authorize",
	ACCESS_CLIENT_ID: "test-access-client",
	ACCESS_CLIENT_SECRET: "test-access-secret",
	ACCESS_JWKS_URL: "https://access.example/jwks",
	ACCESS_TOKEN_URL: "https://access.example/token",
	COOKIE_ENCRYPTION_KEY: "0000000000000000000000000000000000000000000000000000000000000000",
	NOTION_TOKEN: "test-notion-token",
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
				redirect_uris: [redirectUri],
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
		const form = new URLSearchParams();
		for (const name of ["state", "csrf_token"]) {
			const match = html.match(new RegExp(`name="${name}" value="([^"]+)"`));
			assert.ok(match, `Missing consent field: ${name}`);
			form.set(name, match[1]);
		}
		const approval = await worker.fetch("https://concierge.j1.io/authorize", {
			method: "POST",
			redirect: "manual",
			headers: { Cookie: consent.headers.get("Set-Cookie").split(";")[0] },
			body: form,
		});
		assert.equal(approval.status, 302);
		const upstreamUrl = new URL(approval.headers.get("Location"));
		assert.equal(upstreamUrl.origin, "https://access.example");
		const callbackUrl = new URL("https://concierge.j1.io/callback");
		callbackUrl.search = new URLSearchParams({
			code: "test-access-code",
			state: upstreamUrl.searchParams.get("state"),
		}).toString();
		const callback = await worker.fetch(callbackUrl, { redirect: "manual" });
		assert.equal(callback.status, 302);
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

function createConciergeHarness(debugEnabled) {
	return createTestHarness({
		root: ROOT,
		workers: [
			{
				bindingOverrides: { BROWSER: "browser-mock" },
				configPath: "./wrangler.jsonc",
				secrets: TEST_SECRETS,
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

async function withMcpClient(options, run) {
	const client = new Client(
		{ name: "concierge-integration-test", version: "1.0.0" },
		options,
	);
	const worker = debugServer.getWorker("concierge");
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
