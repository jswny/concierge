import type { ConnectorTools } from "@cloudflare/codemode";
import { z } from "zod";
import { ObservedConnector } from "../../observed-connector";
import { UsageLog } from "../../usage-logging";
import { ConnectorRequests, createApiUrl, type ApiFailure, type ApiPayload } from "../../connector-requests";
import { apiRequestSchema, parseApiRequest, toToolInputSchema } from "../../connector-inputs";
import { ConnectorImages, isConnectorImage } from "../../connector-images";
import { RESPONSE_TYPES } from "../../response-formats";

const API_ORIGIN = "https://api.ui.com";
const PROXY_PATH = /^\/v1\/connector\/consoles\/[^/]+\/proxy\/(network|protect)\/integration\/v1\//;

const requestSchema = apiRequestSchema({
	methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
	pathPrefix: "/v1/",
	queryArrays: true,
});

const requestInputSchema = toToolInputSchema(requestSchema);

export class UnifiConnector extends ObservedConnector<Env> {
	constructor(ctx: DurableObjectState, env: Env, private readonly requests: ConnectorRequests, private readonly images: ConnectorImages, usage: UsageLog) {
		super(ctx, env, usage);
	}

	name() {
		return "unifi";
	}

	protected instructions() {
		return [
			"Use for pre-authenticated UniFi Site Manager, Network, and Protect APIs through https://api.ui.com, including JPEG camera snapshots.",
			"Consult https://developer.ui.com for the installed application's API version, native methods, paths, query parameters, and bodies. The API does not expose every dashboard feature.",
			"Discover consoles with GET /v1/hosts; preserve data, nextToken, and host id. A host is a console/controller, not each AP, switch, or camera. Host discovery does not guarantee proxy authorization.",
			"Use /v1/connector/consoles/{consoleId}/proxy/network/integration/v1/ or /v1/connector/consoles/{consoleId}/proxy/protect/integration/v1/ for application calls. Encode each returned ID as a URL path segment. For Network, list local sites first at the network prefix plus sites, then use that local siteId for clients/devices/networks; do not substitute a Site Manager site ID.",
			"Cloud Connector requires compatible console firmware (at least 5.0.3); personal keys can proxy only to consoles owned by the key's account. Credentials and API origin are server-owned.",
			"Supports reads and writes permitted by the key. Configuration changes, device actions, and deletes can interrupt connectivity or change security settings. Failed calls do not undo earlier actions; never blindly replay a write with an unknown outcome.",
			"Returns native JSON unchanged, including pagination and per-item outcomes, or null for empty responses. Protect GET cameras/{id}/snapshot returns an opaque, invocation-local JPEG image reference; return that value unchanged (directly or nested in an object/array) in the same invocation to deliver an MCP image. Image bytes are not accessible in Code Mode or retained in durable history. Do not stringify the reference or reuse it in another invocation. Retrieve at most four images totaling 4 MiB per invocation. Only GET calls are automatically replay-safe. No video, other image formats, NAS/Drive, legacy internal APIs, local-network access, file transfer, or WebSocket event subscriptions.",
		].join(" ");
	}

	protected tools(): ConnectorTools {
		return {
			request: {
				description: `Call official UniFi APIs for console discovery and management of networking/Wi-Fi, connected clients, APs, switches, gateways, networks, camera/NVR status, Protect settings and controls, and JPEG camera snapshots. Use native /v1/ Site Manager paths (start with GET /v1/hosts), or /v1/connector/consoles/{consoleId}/proxy/{network|protect}/integration/v1/... for application calls. Encode IDs as path segments. Network siteId values come from the console's Network sites, not Site Manager. Consult developer.ui.com for supported endpoints and installed versions. Authentication is server-owned; permitted writes/deletes are supported and can disrupt network/security settings. Returns native JSON and pagination unchanged, null for empty responses, or an opaque image reference for Protect cameras/{id}/snapshot (${RESPONSE_TYPES.jpeg.mimeType}). Return image references unchanged, directly or nested in an object/array, in the same invocation to deliver MCP images. No raw image bytes in Code Mode; do not stringify references or reuse them across invocations. Retrieve at most four images totaling 4 MiB per invocation. No video, other image formats, NAS/Drive, legacy API, or event streaming.`,
				inputSchema: requestInputSchema,
				execute: async (args, execution) => {
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

					const result = await this.requests.request({
						connector: "UniFi",
						operation: "request",
						readOnly: options.method === "GET",
						url,
						method: options.method,
						format: "json-or-image",
						headers: { "X-API-Key": this.env.UNIFI_API_KEY },
						body: options.body === undefined ? undefined : JSON.stringify(options.body),
						classifyError: classifyUnifiError,
					});

					if (!isConnectorImage(result)) return result;

					if (!execution) throw new Error("Image retrieval requires a Code Mode invocation.");

					return this.images.capture(execution.executionId, result);
				},
			},
		};
	}
}

const errorSchema = z.object({
	message: z.string().optional().catch(undefined),
	code: z.string().optional().catch(undefined),
	traceId: z.string().optional().catch(undefined),
});

function classifyUnifiError(status: number, payload: ApiPayload | undefined): ApiFailure {
	const error = errorSchema.safeParse(payload).data;

	const failure: ApiFailure = {
		message: error?.message,
		code: error?.code,
		requestId: error?.traceId,
	};

	// A proxy timeout does not prove that the console rejected a mutation.
	if (status === 408) {
		failure.retryable = true;
		failure.outcome = "unknown";
	}

	return failure;
}
