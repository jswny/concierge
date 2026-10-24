import { ObservedConnector } from "../../observed-connector";
import { UsageLog } from "../../usage-logging";
import { z } from "zod";
import { GoogleWorkspaceAuth } from "./auth";
import { ConnectorRequests, type ApiFailure, type ApiPayload } from "../../connector-requests";
import { ConnectorHttp, selectApiService } from "../../connector-http";
import { apiRequestSchema } from "../../connector-inputs";
import { defineConnectorTool, type ConciergeTools } from "../../connector-tools";
import { defineConnector } from "../../connector-definition";

export const googleConnector = defineConnector({
	id: "google",
	label: "Google",
	hint: "Call Google Workspace APIs as joe@j1.io through google.request. Gmail email/settings and Google Calendar events, calendars, sharing and availability are enabled; consult official API documentation for request details.",
	create: ({ ctx, env, googleAuth, requests, usage }) => new GoogleConnector(ctx, env, googleAuth, requests, usage),
});

const SERVICES = [
	{
		id: "gmail",
		origin: "https://gmail.googleapis.com",
		pathPrefix: "/gmail/v1/users/me/",
		scopes: [
			"https://mail.google.com/",
			"https://www.googleapis.com/auth/gmail.settings.basic",
			"https://www.googleapis.com/auth/gmail.settings.sharing",
		],
	},
	{
		id: "calendar",
		origin: "https://www.googleapis.com",
		pathPrefix: "/calendar/v3/",
		scopes: ["https://www.googleapis.com/auth/calendar"],
	},
] as const;

const READ_ONLY_POST_PATHS = new Set(["/calendar/v3/freeBusy"]);

const requestSchema = apiRequestSchema({
	methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
	pathPrefix: "/",
	queryArrays: true,
}).safeExtend({
	path: z.string().startsWith("/").describe("Relative API path: /gmail/v1/users/me/ for Gmail or /calendar/v3/ for Calendar. Put query parameters in query."),
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
			"Google Calendar is enabled, including events, calendar lists, calendars, sharing permissions, settings, and free/busy availability.",
			"Consult the current official Google API documentation for endpoint methods, paths, query parameters, and JSON bodies.",
			"Use /gmail/v1/users/me/ paths for Gmail or /calendar/v3/ paths for Calendar. The path selects the API; authentication, scopes, and the impersonated account are managed server-side and cannot be changed by tool arguments.",
			"Calendar IDs are native API IDs; primary selects the impersonated user's primary calendar. Preserve pagination/sync tokens, time zones, recurring events, and per-calendar free/busy errors. Calendar writes can send invitations or notifications according to native API options. No Calendar push notification receiver or MCP event source is implemented.",
		].join(" ");
	}

	protected tools(): ConciergeTools {
		return {
			request: defineConnectorTool({
				schema: requestSchema,
				description:
					"Call a Google Workspace REST API as joe@j1.io. The native path selects the API: /gmail/v1/users/me/ for reading, sending, creating, updating, deleting email and managing settings; /calendar/v3/ for events, calendars, calendar lists, sharing/ACLs, settings and free/busy availability. Calendar ID primary selects the user's primary calendar. Calendar writes can send invitations/notifications through native API options. Preserve native pagination/sync tokens, time zones, recurrence and per-calendar free/busy errors. No Calendar push receiver or MCP events are implemented. Consult official API documentation. Returns the API JSON response, or null for an empty response.",
				execute: (options) => this.request(options),
			}),
		};
	}

	private async request(options: GoogleRequest) {
		const service = selectApiService(options.path, SERVICES);

		return this.http.request(options, {
			origin: service.origin, pathPrefix: service.pathPrefix,
			operation: service.id,
			readOnlyPostPaths: READ_ONLY_POST_PATHS,
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
