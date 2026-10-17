import type { ConnectorTools } from "@cloudflare/codemode";
import { Buffer } from "node:buffer";
import { z } from "zod";
import { ObservedConnector } from "../../observed-connector";
import { UsageLog } from "../../usage-logging";
import { ConnectorRequests, createApiUrl, isRecord, type ApiFailure } from "../../connector-requests";
import { apiRequestSchema, apiScalarSchema, parseApiRequest, toToolInputSchema } from "../../connector-inputs";

const API_ORIGIN = "https://api.twilio.com";
const API_PREFIX = "/2010-04-01/Accounts/";
const requestSchema = apiRequestSchema({
	methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
	pathPrefix: API_PREFIX,
	queryArrays: true,
}).extend({
	path: z.string().startsWith(API_PREFIX).endsWith(".json")
		.describe("Native core REST API .json path under /2010-04-01/Accounts/{AccountSid}/. The literal {AccountSid} placeholder is expanded server-side; native paths for the configured account are also accepted. Put pagination query parameters in query."),
	body: z.record(z.string(), z.union([apiScalarSchema, z.array(apiScalarSchema)]))
		.optional().describe("Native form parameters, preserving Twilio's case-sensitive names such as To, From, Body, MediaUrl. Arrays produce repeated form fields. Stringify nested values only where the endpoint documentation requires a JSON string."),
});
const requestInputSchema = toToolInputSchema(requestSchema);

export class TwilioConnector extends ObservedConnector<Env> {
	constructor(ctx: DurableObjectState, env: Env, private readonly requests: ConnectorRequests, usage: UsageLog) {
		super(ctx, env, usage);
	}

	name() { return "twilio"; }

	protected instructions() {
		return [
			"Use twilio.request for the configured account's core Twilio REST API at https://api.twilio.com: SMS/MMS messages, message history and delivery status, voice calls, phone numbers, and usage. This is not access to the owner's personal phone or iMessage history.",
			"Consult official Twilio documentation for native methods and parameters. Use /2010-04-01/Accounts/{AccountSid}/Messages.json to list or send messages; the literal {AccountSid} placeholder expands to the server-owned account. Returned native paths for that same account are accepted too. Split next_page_uri into path and query; preserve pagination tokens unchanged.",
			"Bodies are encoded as application/x-www-form-urlencoded, not JSON. Preserve native parameter casing; arrays become repeated fields. Responses retain native JSON shapes, statuses, error codes and pagination; empty responses return null.",
			"Sending messages, placing calls, purchasing numbers, and other writes may incur charges. An accepted or queued message is not proof of delivery; inspect its later status. Reads may be retried, but writes are never automatically replayed, even on rate-limit rejections. Verify unknown outcomes before sending again.",
			"Authentication, account identity and origin are server-owned. Use an API key with the required permissions. Account-auth and credential-management (Keys, SigningKeys, Tokens) endpoints are excluded to avoid exposing reusable credentials. No caller-supplied authentication, alternate Twilio product hosts/regions, binary media, webhook receiver, polling daemon, or automatic agent wakeups are provided. Incoming replies can be read from the Messages API when requested.",
		].join(" ");
	}

	protected tools(): ConnectorTools {
		return {
			request: {
				description: "Call the core Twilio REST API with server-owned API-key authentication. Supports SMS/MMS sending, incoming/outgoing message history, delivery status, voice calls, phone numbers and usage, including permitted writes/deletes. Use native /2010-04-01/Accounts/{AccountSid}/... .json paths, query parameters and form body fields; the literal {AccountSid} placeholder expands server-side. Returns native JSON/pagination unchanged or null for empty responses. Messages and calls can incur charges. Account-auth and Keys/SigningKeys/Tokens credential-management endpoints are excluded. No personal phone/iMessage history, binary media delivery, other Twilio API hosts, webhook handling or automatic notifications to agents.",
				inputSchema: requestInputSchema,
				execute: async (args) => {
					const options = parseApiRequest(requestSchema, args);
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
					return this.requests.request({
						connector: "Twilio",
						operation: "request",
						readOnly: options.method === "GET",
						url,
						method: options.method,
						headers: {
							Authorization: `Basic ${Buffer.from(`${keySid}:${secret}`).toString("base64")}`,
							...(body ? { "Content-Type": "application/x-www-form-urlencoded" } : {}),
						},
						body,
						sensitiveValues: [keySid, secret],
						classifyError: classifyTwilioError,
					});
				},
			},
		};
	}
}

function classifyTwilioError(_status: number, payload: unknown): ApiFailure {
	const error = isRecord(payload) ? payload : {};
	return {
		message: typeof error.message === "string" ? error.message : undefined,
		code: typeof error.code === "number" || typeof error.code === "string" ? String(error.code) : undefined,
	};
}
