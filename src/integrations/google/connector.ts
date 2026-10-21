import type { ConnectorTools } from "@cloudflare/codemode";
import { ObservedConnector } from "../../observed-connector";
import { UsageLog } from "../../usage-logging";
import { z } from "zod";
import { GoogleWorkspaceAuth } from "./auth";
import { ConnectorRequests, type ApiFailure, type ApiPayload } from "../../connector-requests";
import { ConnectorHttp } from "../../connector-http";
import { apiRequestSchema } from "../../connector-inputs";
import { defineConnectorTool } from "../../connector-tools";
import { defineConnector } from "../../connector-definition";

export const googleConnector = defineConnector({
	id: "google",
	label: "Google",
	hint: "Call Google Workspace APIs as joe@j1.io through google.request. Gmail email and settings are enabled; consult official API documentation for request details.",
	create: ({ ctx, env, googleAuth, requests, usage }) => new GoogleConnector(ctx, env, googleAuth, requests, usage),
});

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

// SAFETY: SERVICES is a closed, server-owned object; its own enumerable keys are exactly its service names.
const serviceNames = Object.keys(SERVICES) as Array<keyof typeof SERVICES>;

const requestSchema = apiRequestSchema({
	methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
	pathPrefix: SERVICES.gmail.pathPrefix,
	queryArrays: true,
}).safeExtend({
	service: z.enum(serviceNames).describe("Enabled Google Workspace API."),
	body: z.unknown().optional().describe("Optional JSON request body. MIME messages use the Gmail API's base64url raw field."),
});

type GoogleRequest = z.infer<typeof requestSchema>;

export class GoogleConnector extends ObservedConnector<Env> {
	private readonly http: ConnectorHttp;

	constructor(ctx: DurableObjectState, env: Env, private readonly auth: GoogleWorkspaceAuth, requests: ConnectorRequests, usage: UsageLog) {
		super(ctx, env, usage);
		this.http = new ConnectorHttp(requests, googleConnector);
	}

	name() {
		return googleConnector.id;
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
			request: defineConnectorTool({
				schema: requestSchema,
				description:
					"Call a Google Workspace REST API as joe@j1.io. Gmail is enabled for reading, sending, creating, updating, deleting email and managing settings. Consult official API documentation; use relative /gmail/v1/users/me/ paths. Returns the API JSON response, or null for an empty response.",
				execute: (options) => this.request(options),
			}),
		};
	}

	private async request(options: GoogleRequest) {
		const service = SERVICES[options.service];

		return this.http.request(options, {
			origin: service.origin, pathPrefix: service.pathPrefix,
			operation: options.service,
			authenticate: async () => {
				const token = await this.auth.accessToken(service.scopes);

				return { headers: { Authorization: `Bearer ${token}` }, sensitiveValues: [token] };
			},
			onResponse: (response, headers) => {
				if (response.status === 401) this.auth.invalidate(headers.get("Authorization")!.slice(7));
			},
			classifyError: classifyGoogleError,
		});
	}
}

const errorSchema = z.object({
	error: z.object({
		message: z.string().optional().catch(undefined),
		errors: z.array(z.object({ reason: z.string().optional().catch(undefined) }).nullable().catch(null)).optional().catch(undefined),
	}).optional().catch(undefined),
});

function classifyGoogleError(status: number, payload: ApiPayload | undefined): ApiFailure {
	const error = errorSchema.safeParse(payload).data?.error;
	const reasons = error?.errors?.flatMap((entry) => entry ? [entry.reason] : []) ?? [];
	const rateLimited = status === 429 || (status === 403 && reasons.some((reason) => reason === "rateLimitExceeded" || reason === "userRateLimitExceeded"));

	const failure: ApiFailure = {
		message: error?.message,
		code: reasons[0],
	};

	if (rateLimited) {
		failure.category = "rate_limited";
		failure.retryable = true;
	}

	return failure;
}
