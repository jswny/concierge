import { CodemodeConnector, type ConnectorTools } from "@cloudflare/codemode";
import { z } from "zod";
import { ConnectorRequests, createApiUrl, isRecord, type ApiFailure } from "../../connector-requests";
import { apiRequestSchema, parseApiRequest, toToolInputSchema } from "../../connector-inputs";

const PLACES_ORIGIN = "https://places.googleapis.com";
const READ_ONLY_POST_PATHS = new Set([
	"/v1/places:searchText",
	"/v1/places:searchNearby",
	"/v1/places:autocomplete",
]);
const requestSchema = apiRequestSchema({ methods: ["GET", "POST"], pathPrefix: "/v1/" }).extend({
	service: z.literal("places").describe("Enabled Google Maps Platform API. Places API (New) is currently enabled."),
});
const requestInputSchema = toToolInputSchema(requestSchema);

export class MapsConnector extends CodemodeConnector<Env> {
	constructor(ctx: DurableObjectState, env: Env, private readonly requests: ConnectorRequests) {
		super(ctx, env);
	}

	name() {
		return "maps";
	}

	protected instructions() {
		return [
			"Use for public Google Maps business and place data, not private Google Workspace data or personal saved places.",
			"Consult current official Places API (New) documentation for native endpoint methods, /v1 paths, query parameters, and JSON bodies.",
			"Pass required field masks through query.fields or query['$fields']; choose only needed fields because fields affect billing. Do not put field masks in the body.",
			"Preserve Google Maps and third-party attribution, including review author attribution. Do not persistently cache Places content except where Google's policies permit it.",
			"JSON responses are returned unchanged. For photo media, request skipHttpRedirect=true to receive JSON rather than image bytes.",
			"Authentication is managed server-side. Places searches are read-only even though they use POST, but requests may incur Google Maps Platform charges.",
		].join(" ");
	}

	protected tools(): ConnectorTools {
		return {
			request: {
				description: "Send an authenticated Google Maps Platform REST request. Places API (New) supports business/place text and nearby search, details, ratings, rating counts, hours, reviews, and photo references. Consult official API documentation; use native /v1 paths, query (including fields), and JSON bodies. Returns the API JSON response unchanged. Public data only; no personal Google Maps account access.",
				inputSchema: requestInputSchema,
				execute: async (args) => {
					const options = parseApiRequest(requestSchema, args);
					if (!this.env.GOOGLE_MAPS_API_KEY) throw new Error("GOOGLE_MAPS_API_KEY is not configured.");
					const url = createApiUrl(PLACES_ORIGIN, "/v1/", options.path, options.query);
					return this.requests.request({
						connector: "Maps",
						operation: options.service,
						readOnly: options.method === "GET" || READ_ONLY_POST_PATHS.has(url.pathname),
						url,
						method: options.method,
						headers: { "X-Goog-Api-Key": this.env.GOOGLE_MAPS_API_KEY },
						body: options.body === undefined ? undefined : JSON.stringify(options.body),
						classifyError: classifyMapsError,
					});
				},
			},
		};
	}
}

function classifyMapsError(_status: number, payload: unknown): ApiFailure {
	const error = isRecord(payload) && isRecord(payload.error) ? payload.error : {};
	return {
		message: typeof error.message === "string" ? error.message : undefined,
		code: typeof error.status === "string" ? error.status : undefined,
	};
}
