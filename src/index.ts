import { DynamicWorkerExecutor } from "@cloudflare/codemode";
import { codeMcpServer } from "@cloudflare/codemode/mcp";
import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createMcpHandler } from "agents/mcp";
import { z } from "zod";
import { handleAccessRequest } from "./access-handler";

type DebugEnv = Env & {
	CONCIERGE_DEBUG?: string;
};

type TextToolResult = {
	content: Array<{ text: string; type: "text" }>;
	isError?: boolean;
};

function createConciergeServer(env: Env) {
	const server = new McpServer({
		name: "Concierge MCP",
		version: "1.0.0",
	});

	server.tool(
		"read_webpage_as_markdown",
		"Read a public HTTP(S) webpage as Markdown. The page is rendered with Cloudflare Browser Run and waits for networkidle0 before extraction.",
		{
			url: z.string().url().describe("The HTTP(S) webpage URL to render and convert to Markdown."),
		},
		async ({ url }) => readWebpageAsMarkdown(env, url),
	);

	return server;
}

async function readWebpageAsMarkdown(env: Env, url: string): Promise<TextToolResult> {
	const parsedUrl = new URL(url);
	if (!["http:", "https:"].includes(parsedUrl.protocol)) {
		return {
			content: [{ text: "Only HTTP and HTTPS URLs are supported.", type: "text" }],
			isError: true,
		};
	}

	const response = await env.BROWSER.quickAction("markdown", {
		url: parsedUrl.toString(),
		gotoOptions: {
			waitUntil: "networkidle0",
		},
	});
	const payload = (await response.json()) as
		| { result: string; success: true }
		| { errors?: Array<{ code?: number; detail?: string; message: string }>; success: false };

	if (!response.ok || !payload.success) {
		const errors =
			payload.success === false && payload.errors?.length
				? payload.errors
						.map((error) =>
							[error.message, error.detail, error.code && `code ${error.code}`]
								.filter(Boolean)
								.join(" "),
						)
						.join("\n")
				: `Browser Run returned HTTP ${response.status}.`;

		return {
			content: [{ text: errors, type: "text" }],
			isError: true,
		};
	}

	return {
		content: [{ text: payload.result, type: "text" }],
	};
}

async function createConciergeCodeServer(env: Env) {
	const upstream = createConciergeServer(env);
	const executor = new DynamicWorkerExecutor({ loader: env.LOADER });
	return codeMcpServer({ server: upstream, executor });
}

async function handleMcpRequest(request: Request, env: DebugEnv, ctx: ExecutionContext, route: string) {
	const server = await createConciergeCodeServer(env);
	return createMcpHandler(server, { route })(request, env, ctx);
}

const oauthMcpHandler = {
	async fetch(request: Request, env: DebugEnv, ctx: ExecutionContext) {
		return handleMcpRequest(request, env, ctx, "/mcp");
	},
};

const debugMcpHandler = {
	async fetch(request: Request, env: DebugEnv, ctx: ExecutionContext) {
		return handleMcpRequest(request, env, ctx, "/debug/mcp");
	},
};

const oauthProvider = new OAuthProvider<DebugEnv>({
	apiHandler: oauthMcpHandler,
	apiRoute: "/mcp",
	authorizeEndpoint: "/authorize",
	clientRegistrationEndpoint: "/register",
	defaultHandler: { fetch: handleAccessRequest as any },
	tokenEndpoint: "/token",
});

export default {
	fetch(request: Request, env: DebugEnv, ctx: ExecutionContext) {
		const url = new URL(request.url);
		if (url.pathname === "/debug/mcp") {
			if (env.CONCIERGE_DEBUG?.trim().toLowerCase() !== "true") {
				return new Response("Not found", { status: 404 });
			}

			return debugMcpHandler.fetch(request, env, ctx);
		}

		return oauthProvider.fetch(request, env, ctx);
	},
} satisfies ExportedHandler<DebugEnv>;
