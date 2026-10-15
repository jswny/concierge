import { CodemodeConnector, type ConnectorTools } from "@cloudflare/codemode";
import { ConnectorRequests, createApiUrl, isRecord, type ApiFailure } from "../../connector-requests";
import { apiRequestSchema, parseApiRequest, toToolInputSchema } from "../../connector-inputs";

const API_ORIGIN = "https://api.ui.com";
const PROXY_PATH = /^\/v1\/connector\/consoles\/[^/]+\/proxy\/(network|protect)\/integration\/v1\//;
const requestSchema = apiRequestSchema({
	methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
	pathPrefix: "/v1/",
	queryArrays: true,
});
const requestInputSchema = toToolInputSchema(requestSchema);

export class UnifiConnector extends CodemodeConnector<Env> {
	constructor(ctx: DurableObjectState, env: Env, private readonly requests: ConnectorRequests) {
		super(ctx, env);
	}

	name() {
		return "unifi";
	}

	protected instructions() {
		return [
			"Use for pre-authenticated UniFi Site Manager, Network, and Protect JSON APIs through https://api.ui.com.",
			"Consult https://developer.ui.com for the installed application's API version, native methods, paths, query parameters, and bodies. The API does not expose every dashboard feature.",
			"Discover consoles with GET /v1/hosts; preserve data, nextToken, and host id. A host is a console/controller, not each AP, switch, or camera. Host discovery does not guarantee proxy authorization.",
			"Use /v1/connector/consoles/{consoleId}/proxy/network/integration/v1/ or /v1/connector/consoles/{consoleId}/proxy/protect/integration/v1/ for application calls. Encode each returned ID as a URL path segment. For Network, list local sites first at the network prefix plus sites, then use that local siteId for clients/devices/networks; do not substitute a Site Manager site ID.",
			"Cloud Connector requires compatible console firmware (at least 5.0.3); personal keys can proxy only to consoles owned by the key's account. Credentials and API origin are server-owned.",
			"Supports reads and writes permitted by the key. Configuration changes, device actions, and deletes can interrupt connectivity or change security settings. Failed calls do not undo earlier actions; never blindly replay a write with an unknown outcome.",
			"Returns native JSON unchanged, including pagination and per-item outcomes, or null for empty responses. Only GET calls are automatically replay-safe. No NAS/Drive, legacy internal APIs, local-network access, image/video delivery, file transfer, or WebSocket event subscriptions.",
		].join(" ");
	}

	protected tools(): ConnectorTools {
		return {
			request: {
				description: "Call official UniFi APIs for console discovery and management of networking/Wi-Fi, connected clients, APs, switches, gateways, networks, camera/NVR status, and Protect settings and controls. Use native /v1/ Site Manager paths (start with GET /v1/hosts), or /v1/connector/consoles/{consoleId}/proxy/{network|protect}/integration/v1/... for application calls. Encode IDs as path segments. Network siteId values come from the console's Network sites, not Site Manager. Consult developer.ui.com for supported endpoints and installed versions. Authentication is server-owned; permitted writes/deletes are supported and can disrupt network/security settings. Returns native JSON and pagination unchanged, or null for empty responses. JSON HTTP only; no NAS/Drive, legacy API, images/video, or event streaming.",
				inputSchema: requestInputSchema,
				execute: async (args) => {
					const options = parseApiRequest(requestSchema, args);
					const url = createApiUrl(API_ORIGIN, "/v1/", options.path, options.query);
					// The cloud proxy must not become an escape hatch into console-internal APIs.
					if (/%25/i.test(options.path) || url.pathname.includes("//")) {
						throw new Error("UniFi paths cannot contain double encoding or empty path segments.");
					}
					if ((url.pathname === "/v1/connector" || url.pathname.startsWith("/v1/connector/")) && !PROXY_PATH.test(url.pathname)) {
						throw new Error("UniFi cloud proxy paths must target the Network or Protect integration/v1 API.");
					}
					if (!this.env.UNIFI_API_KEY) throw new Error("UNIFI_API_KEY is not configured.");
					return this.requests.request({
						connector: "UniFi",
						operation: "request",
						readOnly: options.method === "GET",
						url,
						method: options.method,
						headers: { "X-API-Key": this.env.UNIFI_API_KEY },
						body: options.body === undefined ? undefined : JSON.stringify(options.body),
						classifyError: classifyUnifiError,
					});
				},
			},
		};
	}
}

function classifyUnifiError(status: number, payload: unknown): ApiFailure {
	const error = isRecord(payload) ? payload : {};
	return {
		message: typeof error.message === "string" ? error.message : undefined,
		code: typeof error.code === "string" ? error.code : undefined,
		requestId: typeof error.traceId === "string" ? error.traceId : undefined,
		// A proxy timeout does not prove that the console rejected a mutation.
		...(status === 408 ? { retryable: true, outcome: "unknown" } as const : {}),
	};
}
