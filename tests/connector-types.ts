import { z } from "zod";
import { apiRequestSchema, apiQueryValueSchema, type QueryValue } from "../src/connector-inputs";
import { defineConnectorTool, type ConciergeTool } from "../src/connector-tools";
import type { ConnectorId } from "../src/connectors";
import type { ConnectorRequests, RequestAuthentication, ApiPayload } from "../src/connector-requests";
import type { ConnectorHttp } from "../src/connector-http";
import type { JsonValue } from "../src/json";

type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2) ? true : false;

type Assert<T extends true> = T;

export type ConnectorIdsAreLiteral = Assert<Equal<ConnectorId, "cloudflare" | "google" | "maps" | "unifi" | "twilio" | "exa" | "kalshi" | "fantasypros">>;

// @ts-expect-error Authentication must explicitly supply its sensitive values, even if empty.
const incompleteAuthentication: RequestAuthentication = { headers: { Authorization: "Bearer test" } };

void incompleteAuthentication;

const approvalTool: ConciergeTool = {
	execute: () => null,
	// @ts-expect-error Concierge does not expose approval/resume controls.
	requiresApproval: true,
};

const rollbackTool: ConciergeTool = {
	execute: () => null,
	// @ts-expect-error Concierge does not expose rollback controls.
	revert: () => {},
};

void approvalTool;

void rollbackTool;

export function checkResponseProfiles(requests: ConnectorRequests, http: ConnectorHttp) {
	const request = { connector: "test", operation: "request", readOnly: true, url: new URL("https://example.com") };
	const json: Promise<JsonValue> = requests.request(request);
	const images: Promise<ApiPayload> = requests.request({ ...request, format: "json-or-image" });
	// @ts-expect-error Image-capable requests cannot be treated as JSON-only responses.
	const invalidJson: Promise<JsonValue> = images;

	const policy = {
		origin: "https://example.com", pathPrefix: "/",
		authenticate: () => ({ headers: {}, sensitiveValues: [] }),
	};

	const restJson: Promise<JsonValue> = http.request({ method: "GET", path: "/" }, policy);
	const restImages: Promise<ApiPayload> = http.request({ method: "GET", path: "/" }, { ...policy, format: "json-or-image" });
	// @ts-expect-error The provider adapter must also preserve image-capable return types.
	const invalidRestJson: Promise<JsonValue> = restImages;

	return { json, images, invalidJson, restJson, restImages, invalidRestJson };
}

const limitedRequest = apiRequestSchema({ methods: ["GET", "POST"], pathPrefix: "/" });

export type MethodLiteralsArePreserved = Assert<Equal<z.infer<typeof limitedRequest>["method"], "GET" | "POST">>;

export type QueryValuesFollowTheSchema = Assert<Equal<QueryValue, z.infer<typeof apiQueryValueSchema>>>;

// @ts-expect-error Unsupported HTTP methods must fail at the authoring boundary.
apiRequestSchema({ methods: ["TRACE"], pathPrefix: "/" });

defineConnectorTool({
	schema: limitedRequest,
	description: "Compile-time input inference check.",
	execute: (args) => {
		const method: "GET" | "POST" = args.method;
		// @ts-expect-error The handler must not receive fields absent from its schema.
		args.nonexistent;

		return method;
	},
});
