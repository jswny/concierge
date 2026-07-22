import { CodemodeConnector, type ConnectorTools } from "@cloudflare/codemode";
import { XOAuthManager } from "./oauth";

const X_API_ORIGIN = "https://api.x.com";
const X_AUTH_TYPES = ["app", "user"] as const;
const X_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"] as const;

type XAuthType = (typeof X_AUTH_TYPES)[number];
type XMethod = (typeof X_METHODS)[number];
type XQueryValue = string | string[];

type XRequestArgs = {
	auth: XAuthType;
	body?: unknown;
	method: XMethod;
	path: string;
	query?: Record<string, XQueryValue>;
};

export class XConnector extends CodemodeConnector<Env> {
	constructor(
		ctx: DurableObjectState,
		env: Env,
		private readonly oauth: XOAuthManager,
	) {
		super(ctx, env);
	}

	name() {
		return "x";
	}

	protected instructions() {
		return [
			"Use for direct access to the X API v2.",
			"Consult the current official X API documentation for the endpoint, required app-only or user-context authentication, method, /2 path, query parameters, and JSON body before calling x.request.",
			"Set auth to app for the server-side app-only bearer token or user for the stored and automatically refreshed user OAuth 2.0 token.",
			"If user authorization is unavailable, call beginAuthorization and return its authorizationUrl so the user can complete the one-time X consent flow.",
			"Use authorizationStatus to check connection state without exposing credentials.",
		].join(" ");
	}

	protected tools(): ConnectorTools {
		return {
			request: {
				description:
					"Send an authenticated request to the X API v2. Consult the current official X API documentation and explicitly choose app-only or user-context authentication for the endpoint.",
				inputSchema: {
					type: "object",
					properties: {
						auth: {
							description:
								"Credential type required by the endpoint: app for app-only bearer authentication, or user for user-context OAuth 2.0.",
							enum: [...X_AUTH_TYPES],
							type: "string",
						},
						method: {
							description: "X API HTTP method.",
							enum: [...X_METHODS],
							type: "string",
						},
						path: {
							description: "Relative X API v2 path beginning with /2/.",
							pattern: "^/2/",
							type: "string",
						},
						query: {
							description: "Optional string or string-array query parameters.",
							type: "object",
							additionalProperties: {
								anyOf: [
									{ type: "string" },
									{
										type: "array",
										items: { type: "string" },
									},
								],
							},
						},
						body: {
							description: "Optional JSON request body documented for the endpoint.",
						},
					},
					required: ["auth", "method", "path"],
					additionalProperties: false,
				},
				execute: async (args) => requestX(this.env, this.oauth, readRequestArgs(args)),
			},
			beginAuthorization: {
				description:
					"Begin the one-time X OAuth 2.0 user authorization flow. Return authorizationUrl so the user can open it and approve access.",
				inputSchema: {
					type: "object",
					properties: {},
					additionalProperties: false,
				},
				outputSchema: {
					type: "object",
					properties: {
						authorizationUrl: { type: "string" },
						expiresAt: { type: "string" },
					},
					required: ["authorizationUrl", "expiresAt"],
					additionalProperties: false,
				},
				execute: () => this.oauth.beginAuthorization(),
			},
			authorizationStatus: {
				description:
					"Report whether X user authorization is connected, without returning access or refresh tokens.",
				inputSchema: {
					type: "object",
					properties: {},
					additionalProperties: false,
				},
				outputSchema: {
					type: "object",
					properties: {
						connected: { type: "boolean" },
						expiresAt: {
							anyOf: [{ type: "string" }, { type: "null" }],
						},
						scopes: {
							type: "array",
							items: { type: "string" },
						},
					},
					required: ["connected", "expiresAt", "scopes"],
					additionalProperties: false,
				},
				execute: () => this.oauth.authorizationStatus(),
			},
		};
	}
}

function readRequestArgs(args: unknown): XRequestArgs {
	if (!isRecord(args)) {
		throw new Error("Expected an X request object.");
	}

	const { auth, body, method, path, query } = args;
	if (typeof auth !== "string" || !X_AUTH_TYPES.includes(auth as XAuthType)) {
		throw new Error(`Expected auth to be one of: ${X_AUTH_TYPES.join(", ")}.`);
	}
	if (typeof method !== "string" || !X_METHODS.includes(method as XMethod)) {
		throw new Error(`Expected method to be one of: ${X_METHODS.join(", ")}.`);
	}
	if (typeof path !== "string" || !path.startsWith("/2/")) {
		throw new Error("Expected path to begin with /2/.");
	}
	if (query !== undefined && !isRecord(query)) {
		throw new Error("Expected query to be an object of string or string-array values.");
	}

	const parsedQuery: Record<string, XQueryValue> = {};
	for (const [key, value] of Object.entries(query ?? {})) {
		if (Array.isArray(value)) {
			if (!value.every((item) => typeof item === "string")) {
				throw new Error(`Expected query parameter ${key} to contain only strings.`);
			}
			parsedQuery[key] = value;
			continue;
		}

		if (typeof value !== "string") {
			throw new Error(`Expected query parameter ${key} to be a string or string array.`);
		}
		parsedQuery[key] = value;
	}

	return {
		auth: auth as XAuthType,
		body,
		method: method as XMethod,
		path,
		query: parsedQuery,
	};
}

async function requestX(env: Env, oauth: XOAuthManager, options: XRequestArgs) {
	const accessToken = await getAccessToken(env, oauth, options.auth);
	const url = createXUrl(options.path, options.query);
	const response = await fetch(url, {
		method: options.method,
		headers: {
			Accept: "application/json",
			Authorization: `Bearer ${accessToken}`,
			"Content-Type": "application/json",
		},
		body:
			options.body === undefined || options.method === "GET"
				? undefined
				: JSON.stringify(options.body),
		redirect: "manual",
	});
	const payload = await readResponsePayload(response);

	if (!response.ok) {
		throw new Error(formatXError(response, payload));
	}

	return payload;
}

async function getAccessToken(env: Env, oauth: XOAuthManager, auth: XAuthType) {
	if (auth === "app") {
		if (!env.X_BEARER_TOKEN) {
			throw new Error("X_BEARER_TOKEN is not configured.");
		}
		return env.X_BEARER_TOKEN;
	}

	const userAccessToken = await oauth.getUserAccessToken();
	if (!userAccessToken) {
		throw new Error(
			"X user authorization is unavailable. Call x.beginAuthorization() and return its authorizationUrl so the user can complete the one-time consent flow.",
		);
	}
	return userAccessToken;
}

function createXUrl(path: string, query: Record<string, XQueryValue> = {}) {
	const url = new URL(path, X_API_ORIGIN);
	if (url.origin !== X_API_ORIGIN || !url.pathname.startsWith("/2/")) {
		throw new Error("X API requests must stay under https://api.x.com/2/.");
	}

	for (const [key, value] of Object.entries(query)) {
		url.searchParams.set(key, Array.isArray(value) ? value.map(String).join(",") : String(value));
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

	const contentType = response.headers.get("Content-Type")?.toLowerCase() ?? "";
	if (contentType.includes("json")) {
		try {
			return JSON.parse(text) as unknown;
		} catch {
			return text;
		}
	}

	return text;
}

function formatXError(response: Response, payload: unknown) {
	const prefix = `X API returned HTTP ${response.status}`;
	const details = formatXErrorPayload(payload);
	const retryAfter = response.headers.get("Retry-After");
	const rateLimitReset = response.headers.get("x-rate-limit-reset");

	return [
		prefix,
		details,
		retryAfter && `Retry-After: ${retryAfter}s`,
		rateLimitReset && `Rate limit resets at Unix time ${rateLimitReset}`,
	]
		.filter(Boolean)
		.join(". ");
}

function formatXErrorPayload(payload: unknown) {
	if (!payload || typeof payload !== "object") {
		return typeof payload === "string" ? payload : "";
	}

	const { detail, errors, title } = payload as {
		detail?: unknown;
		errors?: unknown;
		title?: unknown;
	};
	const messages = [typeof title === "string" && title, typeof detail === "string" && detail];

	if (Array.isArray(errors)) {
		for (const error of errors.slice(0, 5)) {
			if (error && typeof error === "object" && "message" in error) {
				const message = (error as { message?: unknown }).message;
				if (typeof message === "string") {
					messages.push(message);
				}
			}
		}
	}

	return messages.filter(Boolean).join(": ");
}
