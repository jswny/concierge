import { CodemodeConnector, type ConnectorTools } from "@cloudflare/codemode";
import { ConnectorRequests, createApiUrl, isRecord, type ApiFailure } from "./connector-requests";
import { readApiRequestArgs } from "./connector-inputs";

const NOTION_API_BASE = "https://api.notion.com";
const NOTION_VERSION = "2026-03-11";
const NOTION_METHODS = ["GET", "POST", "PATCH", "DELETE"];

export class NotionConnector extends CodemodeConnector<Env> {
	constructor(ctx: DurableObjectState, env: Env, private readonly requests: ConnectorRequests) {
		super(ctx, env);
	}

	name() {
		return "notion";
	}

	protected instructions() {
		return [
			"Use for direct access to the Notion REST API.",
			"Consult the current official Notion API documentation for the endpoint method, /v1 path, query parameters, and JSON body before calling notion.request.",
			"Requests use the server-side NOTION_TOKEN and can read, create, update, and delete resources permitted by that token.",
		].join(" ");
	}

	protected tools(): ConnectorTools {
		return {
			request: {
				description:
					"Send an authenticated request to the Notion REST API. Consult the current official Notion API documentation for the endpoint's method, relative /v1 path, query parameters, and JSON body.",
				inputSchema: {
					type: "object",
					properties: {
						method: {
							description: "Notion API HTTP method.",
							enum: [...NOTION_METHODS],
							type: "string",
						},
						path: {
							description: "Relative Notion API path beginning with /v1/.",
							pattern: "^/v1/",
							type: "string",
						},
						query: {
							description: "Optional scalar query parameters.",
							type: "object",
							additionalProperties: {
								type: ["boolean", "number", "string"],
							},
						},
						body: {
							description: "Optional JSON request body documented for the endpoint.",
						},
					},
					required: ["method", "path"],
					additionalProperties: false,
				},
				execute: async (args) => {
					const options = readApiRequestArgs(args, { methods: NOTION_METHODS, pathPrefix: "/v1/" });
					if (!this.env.NOTION_TOKEN) throw new Error("NOTION_TOKEN is not configured.");
					return this.requests.request({
						connector: "Notion",
						operation: "request",
						readOnly: options.method === "GET",
						url: createApiUrl(NOTION_API_BASE, "/v1/", options.path, options.query),
						method: options.method,
						headers: { Authorization: `Bearer ${this.env.NOTION_TOKEN}`, "Notion-Version": NOTION_VERSION },
						body: options.body === undefined ? undefined : JSON.stringify(options.body),
						format: "json-or-text",
						classifyError: classifyNotionError,
					});
				},
			},
		};
	}
}

function classifyNotionError(status: number, payload: unknown): ApiFailure {
	const data = isRecord(payload) ? payload : {};
	const blocked = isRecord(data.additional_data) && data.additional_data.rate_limit_reason === "public_api_request_blocked";
	return {
		code: typeof data.code === "string" ? data.code : undefined,
		requestId: typeof data.request_id === "string" ? data.request_id : undefined,
		message: typeof data.message === "string" ? data.message : undefined,
		...(blocked ? { category: "permission", retryable: false } as const :
			status === 429 || status === 529 ? { category: "rate_limited", retryable: true, safeToReplay: true, outcome: "rejected" } as const : {}),
	};
}
