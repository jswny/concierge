import type { ConnectorTools } from "@cloudflare/codemode";
import { Buffer } from "node:buffer";
import { z } from "zod";
import { ObservedConnector } from "../../observed-connector";
import { UsageLog } from "../../usage-logging";
import { ConnectorRequests, createApiUrl, type ApiFailure, type ApiPayload } from "../../connector-requests";
import { apiRequestSchema, apiScalarSchema } from "../../connector-inputs";
import { defineConnectorTool } from "../../connector-tools";
import { defineConnector } from "../../connector-definition";

export const twilioConnector = defineConnector({
	id: "twilio",
	label: "Twilio",
	hint: "Use twilio.request for core Twilio REST API access: send SMS/MMS, read incoming/outgoing message history and delivery status, manage voice calls, phone numbers, and usage. Native account-scoped .json paths and form parameters; credentials are server-owned. Writes can incur charges. When inbound webhooks are configured, event-capable clients can separately subscribe to twilio.message.received through MCP Events. No personal iMessage history or binary media delivery.",
	create: ({ ctx, env, requests, usage }) => new TwilioConnector(ctx, env, requests, usage),
});

const API_ORIGIN = "https://api.twilio.com";
const API_PREFIX = "/2010-04-01/Accounts/";

const requestSchema = apiRequestSchema({
	methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
	pathPrefix: API_PREFIX,
	queryArrays: true,
}).safeExtend({
	path: z.string().startsWith(API_PREFIX).endsWith(".json")
		.describe("Native core REST API .json path under /2010-04-01/Accounts/{AccountSid}/. The literal {AccountSid} placeholder is expanded server-side; native paths for the configured account are also accepted. Put pagination query parameters in query."),
	body: z.record(z.string(), z.union([apiScalarSchema, z.array(apiScalarSchema)]))
		.optional().describe("Native form parameters, preserving Twilio's case-sensitive names such as To, From, Body, MediaUrl. Arrays produce repeated form fields. Stringify nested values only where the endpoint documentation requires a JSON string."),
});

export class TwilioConnector extends ObservedConnector<Env> {
	constructor(ctx: DurableObjectState, env: Env, private readonly requests: ConnectorRequests, usage: UsageLog) {
		super(ctx, env, usage);
	}

	name() { return twilioConnector.id; }

	protected instructions() {
		return [
			"Use twilio.request for the configured account's core Twilio REST API at https://api.twilio.com: SMS/MMS messages, message history and delivery status, voice calls, phone numbers, and usage. This is not access to the owner's personal phone or iMessage history.",
			"Consult official Twilio documentation for native methods and parameters. Use /2010-04-01/Accounts/{AccountSid}/Messages.json to list or send messages; the literal {AccountSid} placeholder expands to the server-owned account. Returned native paths for that same account are accepted too. Split next_page_uri into path and query; preserve pagination tokens unchanged.",
			"Bodies are encoded as application/x-www-form-urlencoded, not JSON. Preserve native parameter casing; arrays become repeated fields. Responses retain native JSON shapes, statuses, error codes and pagination; empty responses return null.",
			"Sending messages, placing calls, purchasing numbers, and other writes may incur charges. An accepted or queued message is not proof of delivery; inspect its later status. Reads may be retried, but writes are never automatically replayed, even on rate-limit rejections. Verify unknown outcomes before sending again.",
			"Authentication, account identity and origin are server-owned. Use an API key with the required permissions. Account-auth and credential-management (Keys, SigningKeys, Tokens) endpoints are excluded to avoid exposing reusable credentials. No caller-supplied authentication, alternate Twilio product hosts/regions, binary media or polling daemon. Incoming replies can be read from the Messages API when requested. When configured, event-capable clients can subscribe separately to twilio.message.received through MCP Events; subscriptions are not Code Mode methods. Events do not automatically send replies.",
		].join(" ");
	}

	protected tools(): ConnectorTools {
		return {
			request: defineConnectorTool({
				schema: requestSchema,
				description: "Call the core Twilio REST API with server-owned API-key authentication. Supports SMS/MMS sending, incoming/outgoing message history, delivery status, voice calls, phone numbers and usage, including permitted writes/deletes. Use native /2010-04-01/Accounts/{AccountSid}/... .json paths, query parameters and form body fields; the literal {AccountSid} placeholder expands server-side. Returns native JSON/pagination unchanged or null for empty responses. Messages and calls can incur charges. Account-auth and Keys/SigningKeys/Tokens credential-management endpoints are excluded. No personal phone/iMessage history, binary media delivery or other Twilio API hosts. Configured incoming messages can trigger twilio.message.received for MCP Events clients; subscribe through that protocol, not this method.",
				execute: async (options) => {
					const { TWILIO_ACCOUNT_SID: accountSid, TWILIO_API_KEY_SID: keySid, TWILIO_API_KEY_SECRET: secret } = this.env;

					if (!accountSid || !keySid || !secret) {
						throw new Error("TWILIO_ACCOUNT_SID, TWILIO_API_KEY_SID and TWILIO_API_KEY_SECRET must be configured.");
					}

					if (!/^AC[0-9a-f]{32}$/i.test(accountSid) || !/^SK[0-9a-f]{32}$/i.test(keySid)) {
						throw new Error("Twilio requires a valid Account SID and API Key SID.");
					}

					const path = options.path.replace("{AccountSid}", accountSid);
					const prefix = `${API_PREFIX}${accountSid}/`;
					const url = createApiUrl(API_ORIGIN, prefix, path, options.query);

					if (/%25/i.test(path) || url.pathname.includes("//")) {
						throw new Error("Twilio paths cannot contain double encoding or empty path segments.");
					}

					if (/^(Keys|SigningKeys|Tokens)(\/|\.json$)/i.test(decodeURIComponent(url.pathname.slice(prefix.length)))) {
						throw new Error("Twilio credential-management endpoints are not exposed.");
					}

					const body = options.body === undefined ? undefined : new URLSearchParams();

					if (body) for (const [key, value] of Object.entries(options.body ?? {})) {
						for (const item of Array.isArray(value) ? value : [value]) body.append(key, String(item));
					}

					const encoded = Buffer.from(`${keySid}:${secret}`).toString("base64");
					const headers = new Headers();

					if (body) headers.set("Content-Type", "application/x-www-form-urlencoded");

					return this.requests.request({
						connector: twilioConnector.label,
						operation: "request",
						readOnly: options.method === "GET",
						url,
						method: options.method,
						headers,
						authenticate: () => ({ headers: { Authorization: `Basic ${encoded}` }, sensitiveValues: [keySid, secret, encoded] }),
						body,
						classifyError: classifyTwilioError,
					});
				},
			}),
		};
	}
}

const errorSchema = z.object({
	message: z.string().optional().catch(undefined),
	code: z.union([z.number(), z.string()]).optional().catch(undefined),
});

function classifyTwilioError(_status: number, payload: ApiPayload | undefined): ApiFailure {
	const error = errorSchema.safeParse(payload).data;

	return {
		message: error?.message,
		code: error?.code === undefined ? undefined : String(error.code),
	};
}
