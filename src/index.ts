import {
	createCodemodeRuntime,
	DynamicWorkerExecutor,
	truncateResult,
	type ProxyToolOutput,
} from "@cloudflare/codemode";
import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { DurableObject } from "cloudflare:workers";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createMcpHandler } from "agents/mcp";
import { z } from "zod";
import { handleAccessRequest } from "./access-handler";
import { CloudflareConnector } from "./cloudflare-connector";

export { CodemodeRuntime } from "@cloudflare/codemode";

type DebugEnv = Env & {
	CONCIERGE_DEBUG?: string;
};

type TextToolResult = {
	content: Array<{ text: string; type: "text" }>;
	isError?: boolean;
};

function createConciergeServer(ctx: DurableObjectState, env: DebugEnv) {
	const server = new McpServer({
		name: "Concierge MCP",
		version: "1.0.0",
	});
	const runtime = createCodemodeRuntime({
		connectors: [new CloudflareConnector(ctx, env)],
		ctx,
		executor: new DynamicWorkerExecutor({ loader: env.LOADER }),
		transformResult: (result) => truncateResult(result),
	});
	const codeTool = runtime.tool({
		connectorHints: {
			cloudflare: "Read rendered public webpages as Markdown with Cloudflare Browser Run.",
		},
	});

	server.registerTool(
		"code",
		{
			description: createConciergeCodeToolDescription(codeTool.description),
			inputSchema: {
				code: z.string().describe("JavaScript async arrow function to execute."),
			},
		},
		async ({ code }, options) => formatCodeToolOutput(await codeTool.execute({ code }, options)),
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
		.map((line) => line.replaceAll(" and saved snippets", ""));

	return appendMarkdownSection(
		lines.join("\n").trim(),
		"Output Format",
		[
			"The MCP tool result is the single value returned by the async function. Return any value the model should receive for later reasoning; console logs and intermediate values are not returned.",
			"If multiple values are needed, return one object that contains them, e.g. `return { first, second };`.",
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
		return {
			content: [{ text: stringifyToolResult(output.result), type: "text" }],
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

function handleMcpRequest(request: Request, env: DebugEnv) {
	return env.CONCIERGE_MCP.getByName("default").fetch(request);
}

export class ConciergeMcpRuntime extends DurableObject<DebugEnv> {
	fetch(request: Request) {
		const route = new URL(request.url).pathname === "/debug/mcp" ? "/debug/mcp" : "/mcp";
		const server = createConciergeServer(this.ctx, this.env);
		return createMcpHandler(server, { route })(
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
