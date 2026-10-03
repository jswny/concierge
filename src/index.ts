import {
	createCodemodeRuntime,
	DynamicWorkerExecutor,
	truncateResult,
	type ProxyToolOutput,
} from "@cloudflare/codemode";
import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { DurableObject } from "cloudflare:workers";
import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler } from "agents/mcp/server";
import { z } from "zod";
import { handleAccessRequest } from "./access-handler";
import { CloudflareConnector } from "./cloudflare-connector";
import { GoogleWorkspaceAuth } from "./integrations/google/auth";
import { GoogleConnector } from "./integrations/google/connector";
import { MapsConnector } from "./integrations/maps/connector";
import { NotionConnector } from "./notion-connector";
import { ConnectorRequests } from "./connector-requests";

export { CodemodeRuntime } from "@cloudflare/codemode";

type DebugEnv = Env & {
	CONCIERGE_DEBUG?: string;
};

type TextToolResult = {
	content: Array<{ text: string; type: "text" }>;
	isError?: boolean;
	structuredContent?: Record<string, unknown>;
};

const MCP_ALLOWED_HOSTNAMES = ["concierge.j1.io", "localhost", "127.0.0.1", "[::1]"];

function createConciergeServer(
	ctx: DurableObjectState,
	env: DebugEnv,
	googleAuth: GoogleWorkspaceAuth,
	requests: ConnectorRequests,
) {
	const server = new McpServer({
		name: "Concierge MCP",
		version: "1.0.0",
	});
	const runtime = createCodemodeRuntime({
		connectors: [
			new CloudflareConnector(ctx, env, requests),
			new NotionConnector(ctx, env, requests),
			new GoogleConnector(ctx, env, googleAuth, requests),
			new MapsConnector(ctx, env, requests),
		],
		ctx,
		executor: new DynamicWorkerExecutor({ loader: env.LOADER }),
		transformResult: (result) => truncateResult(result),
	});
	const codeToolDescription = runtime.tool({
		connectorHints: {
			cloudflare: "Read rendered public webpages as Markdown with Cloudflare Browser Run.",
			google:
				"Call Google Workspace APIs as joe@j1.io through google.request. Gmail email and settings are enabled; consult official API documentation for request details.",
			maps:
				"Search public businesses and places, and read ratings, rating counts, hours, and details through maps.request using Places API (New). Consult official API documentation; pass field masks in query.fields. Requests may incur charges; select only needed fields and preserve Google Maps attribution.",
			notion:
				"Call the Notion REST API through notion.request with the server-side NOTION_TOKEN. Consult the current official Notion API documentation for request details.",
		},
	}).description;

	server.registerTool(
		"code",
		{
			description: createConciergeCodeToolDescription(codeToolDescription),
			inputSchema: {
				code: z.string().describe("JavaScript async arrow function to execute."),
			},
			outputSchema: {
				result: z
					.unknown()
					.describe("The single JSON-serializable value returned by the async function."),
			},
			annotations: {
				readOnlyHint: false,
				destructiveHint: true,
				idempotentHint: false,
				openWorldHint: true,
			},
		},
		async ({ code }) => formatCodeToolOutput(await runtime.execute({ code })),
	);

	return server;
}

function createConciergeCodeToolDescription(defaultDescription: string) {
	const withoutSnippets = removeMarkdownSection(defaultDescription, "Snippets");
	const lines = withoutSnippets
		.split("\n")
		.filter((line) => !line.startsWith("- Some methods require approval."))
		.filter((line) => !line.startsWith('- A result with `status: "paused"`'))
		.filter((line) => !line.startsWith("- `codemode.step("))
		.filter((line) => !line.startsWith("- All code outside connector calls"))
		.map((line) =>
			line
				.replaceAll(" and saved snippets", "")
				.replace('codemode.search("short intent phrase")', 'codemode.search("short method capability")'),
		);
	const withToolDiscovery = appendMarkdownSection(
		lines.join("\n").trim(),
		"Tool Discovery",
		[
			"`codemode.search` searches connector method names and descriptions; it does not search the web or external content.",
			"Search with only a short method capability, such as `read webpage markdown`. Do not include the target site, URL, resource name, or desired content in the query.",
			"Example: to read reviews from a Google Maps page, search for `read webpage markdown`, describe the matched method, then pass the Google Maps URL to that method. Do not search for `Google Maps reviews`.",
			"If discovery returns no results, retry with a shorter, more general capability phrase before concluding that no connector method exists.",
		].join("\n"),
	);

	const withOutputFormat = appendMarkdownSection(
		withToolDiscovery,
		"Output Format",
		[
			"The Code Mode result is the single value returned by the async function. Return any value the model should receive for later reasoning; console logs and intermediate values are not returned.",
			"If multiple values are needed, return one object that contains them, e.g. `return { first, second };`.",
		].join("\n"),
	);
	return appendMarkdownSection(
		withOutputFormat,
		"Failure Recovery",
		[
			"A failed code invocation does not undo earlier connector calls. Do not blindly rerun the whole function; inspect earlier side effects before continuing.",
			"Connector errors include retryability, replay safety, and write outcomes. Do not replay a write with `outcome=unknown` or `outcome=succeeded`; verify external state first. Respect `Retry-After` guidance and use smaller batches or responses when requested.",
		].join("\n"),
	);
}

function removeMarkdownSection(markdown: string, heading: string) {
	const marker = `\n## ${heading}\n`;
	const start = markdown.indexOf(marker);
	if (start === -1) {
		return markdown;
	}

	const next = markdown.indexOf("\n## ", start + marker.length);
	if (next === -1) {
		return markdown.slice(0, start).trimEnd();
	}

	return `${markdown.slice(0, start)}${markdown.slice(next)}`;
}

function appendMarkdownSection(markdown: string, heading: string, body: string) {
	return `${markdown}\n\n## ${heading}\n\n${body}`;
}

function formatCodeToolOutput(output: ProxyToolOutput): TextToolResult {
	if (output.status === "completed") {
		const result = normalizeStructuredResult(output.result);
		return {
			content: [{ text: stringifyToolResult(output.result), type: "text" }],
			structuredContent: { result },
		};
	}

	if (output.status === "paused") {
		return {
			content: [
				{
					text: "Approval-required Code Mode tools are not supported by this MCP server.",
					type: "text",
				},
			],
			isError: true,
		};
	}

	return {
		content: [{ text: output.error, type: "text" }],
		isError: true,
	};
}

function stringifyToolResult(result: unknown) {
	if (typeof result === "string") {
		return result;
	}
	if (result === undefined) {
		return "";
	}

	try {
		return JSON.stringify(result, null, 2);
	} catch {
		return String(result);
	}
}

function normalizeStructuredResult(result: unknown) {
	return result === undefined ? null : result;
}

function handleMcpRequest(request: Request, env: DebugEnv) {
	return env.CONCIERGE_MCP.getByName("default").fetch(request);
}

export class ConciergeMcpRuntime extends DurableObject<DebugEnv> {
	private readonly requests = new ConnectorRequests();
	private readonly googleAuth = new GoogleWorkspaceAuth(this.env, this.requests);

	fetch(request: Request) {
		const pathname = new URL(request.url).pathname;
		const route = pathname === "/debug/mcp" ? "/debug/mcp" : "/mcp";
		return createMcpHandler(() => createConciergeServer(this.ctx, this.env, this.googleAuth, this.requests), {
			allowedHostnames: MCP_ALLOWED_HOSTNAMES,
			route,
		})(
			request,
			this.env,
			this.ctx as unknown as ExecutionContext,
		);
	}
}

const oauthMcpHandler = {
	async fetch(request: Request, env: DebugEnv, _ctx?: ExecutionContext) {
		return handleMcpRequest(request, env);
	},
};

const debugMcpHandler = {
	async fetch(request: Request, env: DebugEnv, _ctx?: ExecutionContext) {
		return handleMcpRequest(request, env);
	},
};

const oauthProvider = new OAuthProvider<DebugEnv>({
	apiHandler: oauthMcpHandler,
	apiRoute: "/mcp",
	authorizeEndpoint: "/authorize",
	clientIdMetadataDocumentEnabled: true,
	defaultHandler: { fetch: handleAccessRequest },
	resourceMetadata: { resource: "https://concierge.j1.io/mcp" },
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
