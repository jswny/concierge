import { CodemodeConnector, type ConnectorTools } from "@cloudflare/codemode";

const NOTION_API_BASE = "https://api.notion.com";
const NOTION_VERSION = "2026-03-11";
const NOTION_METHODS = ["GET", "POST", "PATCH", "DELETE"];

type NotionRequestArgs = {
	body?: unknown;
	method: string;
	path: string;
	query?: Record<string, boolean | number | string>;
};

export class NotionConnector extends CodemodeConnector<Env> {
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
				execute: async (args) => requestNotion(this.env, readRequestArgs(args)),
			},
		};
	}
}

function readRequestArgs(args: unknown): NotionRequestArgs {
	if (!isRecord(args)) {
		throw new Error("Expected a Notion request object.");
	}

	const { body, method, path, query } = args;
	if (typeof method !== "string" || !NOTION_METHODS.includes(method)) {
		throw new Error(`Expected method to be one of: ${NOTION_METHODS.join(", ")}.`);
	}
	if (typeof path !== "string" || !path.startsWith("/v1/")) {
		throw new Error("Expected path to begin with /v1/.");
	}
	if (query !== undefined && !isRecord(query)) {
		throw new Error("Expected query to be an object of scalar values.");
	}

	const parsedQuery: Record<string, boolean | number | string> = {};
	for (const [key, value] of Object.entries(query ?? {})) {
		if (!["boolean", "number", "string"].includes(typeof value)) {
			throw new Error(`Expected query parameter ${key} to be a scalar value.`);
		}
		parsedQuery[key] = value as boolean | number | string;
	}

	return { body, method, path, query: parsedQuery };
}

async function requestNotion(env: Env, options: NotionRequestArgs) {
	if (!env.NOTION_TOKEN) {
		throw new Error("NOTION_TOKEN is not configured.");
	}

	const url = createNotionUrl(options.path, options.query);
	const response = await fetch(url, {
		method: options.method,
		headers: {
			Accept: "application/json",
			Authorization: `Bearer ${env.NOTION_TOKEN}`,
			"Content-Type": "application/json",
			"Notion-Version": NOTION_VERSION,
		},
		body:
			options.body === undefined || options.method === "GET"
				? undefined
				: JSON.stringify(options.body),
		redirect: "error",
	});
	const payload = await readResponsePayload(response);

	if (!response.ok) {
		throw new Error(formatNotionError(response, payload));
	}

	return payload;
}

function createNotionUrl(path: string, query: Record<string, boolean | number | string> = {}) {
	const url = new URL(path, NOTION_API_BASE);
	if (url.origin !== NOTION_API_BASE || !url.pathname.startsWith("/v1/")) {
		throw new Error("Notion requests must stay under https://api.notion.com/v1/.");
	}

	for (const [key, value] of Object.entries(query)) {
		url.searchParams.append(key, String(value));
	}

	return url;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

async function readResponsePayload(response: Response) {
	const text = await response.text();
	if (!text) {
		return null;
	}

	try {
		return JSON.parse(text) as unknown;
	} catch {
		return text;
	}
}

function formatNotionError(response: Response, payload: unknown) {
	const retryAfter = response.headers.get("Retry-After");
	const prefix = `Notion API returned HTTP ${response.status}`;

	if (payload && typeof payload === "object") {
		const { code, message } = payload as { code?: unknown; message?: unknown };
		const details = [typeof code === "string" && code, typeof message === "string" && message]
			.filter(Boolean)
			.join(": ");

		return [prefix, details, retryAfter && `Retry-After: ${retryAfter}s`]
			.filter(Boolean)
			.join(". ");
	}

	return [prefix, typeof payload === "string" && payload, retryAfter && `Retry-After: ${retryAfter}s`]
		.filter(Boolean)
		.join(". ");
}
