import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { McpAgent } from "agents/mcp";
import { z } from "zod";
import { handleAccessRequest } from "./access-handler";
import type { Props } from "./workers-oauth-utils";

export class MyMCP extends McpAgent<Env, Record<string, never>, Props> {
	server = new McpServer({
		name: "Concierge MCP",
		version: "1.0.0",
	});

	async init() {
		this.server.tool(
			"read_webpage_as_markdown",
			"Read a public HTTP(S) webpage as Markdown. The page is rendered with Cloudflare Browser Run and waits for networkidle0 before extraction.",
			{
				url: z.string().url().describe("The HTTP(S) webpage URL to render and convert to Markdown."),
			},
			async ({ url }) => {
				const parsedUrl = new URL(url);
				if (!["http:", "https:"].includes(parsedUrl.protocol)) {
					return {
						content: [{ text: "Only HTTP and HTTPS URLs are supported.", type: "text" }],
						isError: true,
					};
				}

				const response = await this.env.BROWSER.quickAction("markdown", {
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
			},
		);
	}
}

export default new OAuthProvider({
	apiHandler: MyMCP.serve("/mcp"),
	apiRoute: "/mcp",
	authorizeEndpoint: "/authorize",
	clientRegistrationEndpoint: "/register",
	defaultHandler: { fetch: handleAccessRequest as any },
	tokenEndpoint: "/token",
});
