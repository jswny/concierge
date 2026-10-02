import { CodemodeConnector, type ConnectorTools } from "@cloudflare/codemode";
import { GoogleWorkspaceAuth } from "./auth";

const SERVICES = {
	gmail: {
		origin: "https://gmail.googleapis.com",
		pathPrefix: "/gmail/v1/users/me/",
		scopes: [
			"https://mail.google.com/",
			"https://www.googleapis.com/auth/gmail.settings.basic",
			"https://www.googleapis.com/auth/gmail.settings.sharing",
		],
	},
} as const;
const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"];
type Scalar = boolean | number | string;
type GoogleRequest = {
	service: keyof typeof SERVICES;
	method: string;
	path: string;
	query?: Record<string, Scalar | Scalar[]>;
	body?: unknown;
};

export class GoogleConnector extends CodemodeConnector<Env> {
	constructor(ctx: DurableObjectState, env: Env, private readonly auth: GoogleWorkspaceAuth) {
		super(ctx, env);
	}

	name() {
		return "google";
	}

	protected instructions() {
		return [
			"Use for pre-authenticated Google Workspace REST API access as joe@j1.io.",
			"Gmail is currently enabled, including messages, drafts, labels, sending, deletion, and settings.",
			"Consult the current official Google API documentation for endpoint methods, paths, query parameters, and JSON bodies.",
			"Use /gmail/v1/users/me/ paths. Authentication, scopes, and the impersonated account are managed server-side and cannot be changed by tool arguments.",
		].join(" ");
	}

	protected tools(): ConnectorTools {
		return {
			request: {
				description:
					"Call a Google Workspace REST API as joe@j1.io. Gmail is enabled for reading, sending, creating, updating, deleting email and managing settings. Consult official API documentation; use relative /gmail/v1/users/me/ paths. Returns the API JSON response, or null for an empty response.",
				inputSchema: {
					type: "object",
					properties: {
						service: { type: "string", enum: Object.keys(SERVICES), description: "Enabled Google Workspace API." },
						method: { type: "string", enum: METHODS, description: "API HTTP method." },
						path: { type: "string", pattern: "^/gmail/v1/users/me/", description: "Relative API path, e.g. /gmail/v1/users/me/profile. Put query parameters in query." },
						query: {
							type: "object",
							description: "Optional query parameters. Arrays produce repeated parameters.",
							additionalProperties: {
								anyOf: [
									{ type: ["boolean", "number", "string"] },
									{ type: "array", items: { type: ["boolean", "number", "string"] } },
								],
							},
						},
						body: { description: "Optional JSON request body. MIME messages use the Gmail API's base64url raw field." },
					},
					required: ["service", "method", "path"],
					additionalProperties: false,
				},
				execute: async (args) => this.request(readRequest(args)),
			},
		};
	}

	private async request(options: GoogleRequest) {
		const service = SERVICES[options.service];
		const url = new URL(options.path, service.origin);
		if (
			url.origin !== service.origin || !url.pathname.startsWith(service.pathPrefix) ||
			url.search || url.hash || /%(?:2f|5c|2e)/i.test(url.pathname)
		) {
			throw new Error(`Google ${options.service} paths must begin with ${service.pathPrefix} and stay on the API origin.`);
		}
		for (const [key, value] of Object.entries(options.query ?? {})) {
			if (["access_token", "oauth_token", "key"].includes(key)) {
				throw new Error("Google API credentials are managed server-side.");
			}
			for (const item of Array.isArray(value) ? value : [value]) {
				url.searchParams.append(key, String(item));
			}
		}
		if (options.method === "GET" && options.body !== undefined) {
			throw new Error("GET requests cannot include a body.");
		}
		const token = await this.auth.accessToken(service.scopes);
		const response = await fetch(url, {
			method: options.method,
			headers: {
				Accept: "application/json",
				Authorization: `Bearer ${token}`,
				"Content-Type": "application/json",
			},
			body: options.body === undefined ? undefined : JSON.stringify(options.body),
			redirect: "manual",
			signal: AbortSignal.timeout(30_000),
		});
		if (response.status === 401) this.auth.invalidate(token);
		if (!response.ok) {
			let payload: unknown;
			try { payload = await response.json(); } catch { /* Non-JSON gateway errors carry no API details. */ }
			const message = isRecord(payload) && isRecord(payload.error) && typeof payload.error.message === "string"
				? payload.error.message.replaceAll(token, "[redacted]").slice(0, 2000)
				: "";
			const retryAfter = response.headers.get("Retry-After");
			throw new Error(`Google ${options.service} API returned HTTP ${response.status}.${message ? ` ${message}` : ""}${retryAfter ? ` Retry-After: ${retryAfter}s.` : ""}`);
		}
		const text = await response.text();
		return text ? JSON.parse(text) as unknown : null;
	}
}

function readRequest(args: unknown): GoogleRequest {
	if (!isRecord(args) || Object.keys(args).some((key) => !["service", "method", "path", "query", "body"].includes(key))) {
		throw new Error("Expected a Google request with service, method, path, and optional query/body.");
	}
	const { service, method, path, query, body } = args;
	if (typeof service !== "string" || !Object.prototype.hasOwnProperty.call(SERVICES, service)) {
		throw new Error(`Expected Google service to be one of: ${Object.keys(SERVICES).join(", ")}.`);
	}
	if (typeof method !== "string" || !METHODS.includes(method)) {
		throw new Error(`Expected method to be one of: ${METHODS.join(", ")}.`);
	}
	if (typeof path !== "string" || !path.startsWith(SERVICES[service as keyof typeof SERVICES].pathPrefix)) {
		throw new Error("Expected a relative Google API path for users/me.");
	}
	if (query !== undefined && (!isRecord(query) || Object.values(query).some((value) =>
		!(Array.isArray(value) ? value.every(isScalar) : isScalar(value))))) {
		throw new Error("Expected Google query parameters to be scalar values or arrays of scalar values.");
	}
	return { service: service as keyof typeof SERVICES, method, path, query: query as GoogleRequest["query"], body };
}

function isScalar(value: unknown): value is Scalar {
	return typeof value === "string" || typeof value === "boolean" || (typeof value === "number" && Number.isFinite(value));
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return Boolean(value && typeof value === "object" && !Array.isArray(value));
}
