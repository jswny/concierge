import { ObservedConnector } from "../../observed-connector";
import { UsageLog } from "../../usage-logging";
import { z } from "zod";
import { ConnectorRequests, type ApiFailure, type ApiPayload } from "../../connector-requests";
import { ConnectorHttp, selectApiService } from "../../connector-http";
import { apiRequestSchema } from "../../connector-inputs";
import { defineConnectorTool, type ConciergeTools } from "../../connector-tools";
import { defineConnector } from "../../connector-definition";

export const mapsConnector = defineConnector({
	id: "maps",
	label: "Maps",
	hint: "Use maps.request for public businesses, places, ratings, hours, reviews, directions, travel times, distances, and route matrices through Places API (New) and Routes API. Prefer these APIs over reading Google Maps webpages for supported tasks. Consult official API documentation; pass field masks in query.fields. Requests may incur charges; select only needed fields and preserve Google Maps attribution.",
	create: ({ ctx, env, requests, usage }) => new MapsConnector(ctx, env, requests, usage),
});

const ROUTE_PATHS = new Set(["/directions/v2:computeRoutes", "/distanceMatrix/v2:computeRouteMatrix"]);

const SERVICES = [
	{ id: "places", origin: "https://places.googleapis.com", pathPrefix: "/v1/" },
	{ id: "routes", origin: "https://routes.googleapis.com", pathPrefix: "/", paths: ROUTE_PATHS },
] as const;

const READ_ONLY_POST_PATHS = new Set([
	"/v1/places:searchText",
	"/v1/places:searchNearby",
	"/v1/places:autocomplete",
	...ROUTE_PATHS,
]);

const requestSchema = apiRequestSchema({ methods: ["GET", "POST"], pathPrefix: "/" }).safeExtend({
	path: z.string().startsWith("/").describe("Places: /v1/ paths. Routes: POST /directions/v2:computeRoutes or /distanceMatrix/v2:computeRouteMatrix."),
});

export class MapsConnector extends ObservedConnector<Env> {
	private readonly http: ConnectorHttp;

	constructor(ctx: DurableObjectState, env: Env, requests: ConnectorRequests, usage: UsageLog) {
		super(ctx, env, usage);
		this.http = new ConnectorHttp(requests, mapsConnector);
	}

	name() {
		return mapsConnector.id;
	}

	protected instructions() {
		return [
			"Use for public Google Maps place data and routing, not private Google Workspace data or personal saved places.",
			"Consult current official Places API (New) and Routes API documentation for native endpoints, query parameters, and JSON bodies. The path selects the API: Places uses /v1/ paths; Routes uses POST /directions/v2:computeRoutes or POST /distanceMatrix/v2:computeRouteMatrix.",
			"Pass required field masks through query.fields or query['$fields']; choose only needed fields because fields affect billing. Do not put field masks in the body.",
			"Preserve Google Maps and third-party attribution, including review author attribution. Do not persistently cache Places content except where Google's policies permit it.",
			"JSON responses are returned unchanged. For photo media, request skipHttpRedirect=true to receive JSON rather than image bytes.",
			"Route matrices return an array with per-element outcomes; include originIndex,destinationIndex,status,condition in the field mask and inspect status and condition for each element.",
			"Authentication is managed server-side. Places searches and route calculations are read-only even though they use POST, but requests may incur Google Maps Platform charges. Route matrices are billed per origin-destination element.",
		].join(" ");
	}

	protected tools(): ConciergeTools {
		return {
			request: defineConnectorTool({
				schema: requestSchema,
				description: "Send an authenticated Google Maps Platform REST request. The native path selects Places API (New) under /v1/ or Routes API at POST /directions/v2:computeRoutes and /distanceMatrix/v2:computeRouteMatrix. Places supports business/place text and nearby search, details, ratings, rating counts, hours, reviews, and photo references. Routes supports directions, travel time, distance, traffic-aware routing, and origin-destination route matrices. Consult official API documentation; use native paths, query (including fields), and JSON bodies. Returns the API JSON response unchanged. Public data only; no personal Google Maps account access.",
				execute: async (options) => {
					const service = selectApiService(options.path, SERVICES);

					if (service.id === "routes" && options.method !== "POST") throw new Error("Routes endpoints require POST.");

					if (!this.env.GOOGLE_MAPS_API_KEY) throw new Error("GOOGLE_MAPS_API_KEY is not configured.");

					return this.http.request(options, {
						origin: service.origin,
						pathPrefix: service.pathPrefix,
						operation: service.id,
						readOnlyPostPaths: READ_ONLY_POST_PATHS,
						authenticate: () => ({ headers: { "X-Goog-Api-Key": this.env.GOOGLE_MAPS_API_KEY }, sensitiveValues: [this.env.GOOGLE_MAPS_API_KEY] }),
						classifyError: classifyMapsError,
					});
				},
			}),
		};
	}
}

const errorSchema = z.object({
	error: z.object({
		message: z.string().optional().catch(undefined),
		status: z.string().optional().catch(undefined),
	}).optional().catch(undefined),
});

function classifyMapsError(_status: number, payload: ApiPayload | undefined): ApiFailure {
	const error = errorSchema.safeParse(payload).data?.error;

	return {
		message: error?.message,
		code: error?.status,
	};
}
