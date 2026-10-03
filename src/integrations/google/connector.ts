import { CodemodeConnector, type ConnectorTools } from "@cloudflare/codemode";
import { z } from "zod";
import { GoogleWorkspaceAuth } from "./auth";
import { ConnectorRequests, createApiUrl, isRecord, type ApiFailure } from "../../connector-requests";
import { apiRequestSchema, parseApiRequest, toToolInputSchema } from "../../connector-inputs";

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
const requestSchema = apiRequestSchema({
	methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
	pathPrefix: SERVICES.gmail.pathPrefix,
	queryArrays: true,
}).extend({
	service: z.enum(Object.keys(SERVICES) as Array<keyof typeof SERVICES>).describe("Enabled Google Workspace API."),
	body: z.unknown().optional().describe("Optional JSON request body. MIME messages use the Gmail API's base64url raw field."),
});
const requestInputSchema = toToolInputSchema(requestSchema);
type GoogleRequest = z.infer<typeof requestSchema>;

export class GoogleConnector extends CodemodeConnector<Env> {
	constructor(ctx: DurableObjectState, env: Env, private readonly auth: GoogleWorkspaceAuth, private readonly requests: ConnectorRequests) {
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
				inputSchema: requestInputSchema,
				execute: async (args) => this.request(parseApiRequest(requestSchema, args)),
			},
		};
	}

	private async request(options: GoogleRequest) {
		const service = SERVICES[options.service];
		const url = createApiUrl(service.origin, service.pathPrefix, options.path, options.query);
		return this.requests.request({
			connector: "Google",
			operation: options.service,
			readOnly: options.method === "GET",
			url,
			method: options.method,
			headers: async () => ({ Authorization: `Bearer ${await this.auth.accessToken(service.scopes)}` }),
			body: options.body === undefined ? undefined : JSON.stringify(options.body),
			onResponse: (response, headers) => {
				if (response.status === 401) this.auth.invalidate(headers.get("Authorization")!.slice(7));
			},
			classifyError: classifyGoogleError,
		});
	}
}

function classifyGoogleError(status: number, payload: unknown): ApiFailure {
	const error = isRecord(payload) && isRecord(payload.error) ? payload.error : {};
	const reasons = Array.isArray(error.errors) ? error.errors.filter(isRecord).map((entry) => entry.reason) : [];
	const rateLimited = status === 429 || (status === 403 && reasons.some((reason) => reason === "rateLimitExceeded" || reason === "userRateLimitExceeded"));
	return {
		message: typeof error.message === "string" ? error.message : undefined,
		code: typeof reasons[0] === "string" ? reasons[0] : undefined,
		...(rateLimited ? { category: "rate_limited", retryable: true } as const : {}),
	};
}
