import type { ConnectorTools } from "@cloudflare/codemode";
import { ObservedConnector } from "../../observed-connector";
import { UsageLog } from "../../usage-logging";
import { z } from "zod";
import { ConnectorRequests, createApiUrl, type ApiFailure, type ApiPayload } from "../../connector-requests";
import { apiRequestSchema } from "../../connector-inputs";
import { defineConnectorTool } from "../../connector-tools";

const PLACES_ORIGIN = "https://places.googleapis.com";
const ROUTES_ORIGIN = "https://routes.googleapis.com";
const ROUTE_PATHS = new Set(["/directions/v2:computeRoutes", "/distanceMatrix/v2:computeRouteMatrix"]);

const READ_ONLY_POST_PATHS = new Set([
	"/v1/places:searchText",
	"/v1/places:searchNearby",
	"/v1/places:autocomplete",
	...ROUTE_PATHS,
]);

const requestSchema = apiRequestSchema({ methods: ["GET", "POST"], pathPrefix: "/" }).safeExtend({
	service: z.enum(["places", "routes"]).describe("Places API (New) for public place data; Routes API for directions, travel time, distance, and matrices."),
	path: z.string().startsWith("/").describe("Places: /v1/ paths. Routes: POST /directions/v2:computeRoutes or /distanceMatrix/v2:computeRouteMatrix."),
}).superRefine((options, ctx) => {
	if (options.service === "places") {
		if (!options.path.startsWith("/v1/")) ctx.addIssue({ code: "custom", path: ["path"], message: "Places paths must begin with /v1/." });
	} else {
		if (options.method !== "POST") ctx.addIssue({ code: "custom", path: ["method"], message: "Routes endpoints require POST." });

		if (!ROUTE_PATHS.has(options.path)) ctx.addIssue({ code: "custom", path: ["path"], message: "Expected /directions/v2:computeRoutes or /distanceMatrix/v2:computeRouteMatrix." });
	}
});

export class MapsConnector extends ObservedConnector<Env> {
	constructor(ctx: DurableObjectState, env: Env, private readonly requests: ConnectorRequests, usage: UsageLog) {
		super(ctx, env, usage);
	}

	name() {
		return "maps";
	}

	protected instructions() {
		return [
			"Use for public Google Maps place data and routing, not private Google Workspace data or personal saved places.",
			"Consult current official Places API (New) and Routes API documentation for native endpoints, query parameters, and JSON bodies. Places uses /v1 paths; Routes uses POST /directions/v2:computeRoutes or POST /distanceMatrix/v2:computeRouteMatrix.",
			"Pass required field masks through query.fields or query['$fields']; choose only needed fields because fields affect billing. Do not put field masks in the body.",
			"Preserve Google Maps and third-party attribution, including review author attribution. Do not persistently cache Places content except where Google's policies permit it.",
			"JSON responses are returned unchanged. For photo media, request skipHttpRedirect=true to receive JSON rather than image bytes.",
			"Route matrices return an array with per-element outcomes; include originIndex,destinationIndex,status,condition in the field mask and inspect status and condition for each element.",
			"Authentication is managed server-side. Places searches and route calculations are read-only even though they use POST, but requests may incur Google Maps Platform charges. Route matrices are billed per origin-destination element.",
		].join(" ");
	}

	protected tools(): ConnectorTools {
		return {
			request: defineConnectorTool({
				schema: requestSchema,
				description: "Send an authenticated Google Maps Platform REST request. Places API (New) supports business/place text and nearby search, details, ratings, rating counts, hours, reviews, and photo references. Routes API supports directions, travel time, distance, traffic-aware routing, and origin-destination route matrices. Consult official API documentation; use native paths, query (including fields), and JSON bodies. Returns the API JSON response unchanged. Public data only; no personal Google Maps account access.",
				execute: async (options) => {
					if (!this.env.GOOGLE_MAPS_API_KEY) throw new Error("GOOGLE_MAPS_API_KEY is not configured.");

					const url = options.service === "places"
						? createApiUrl(PLACES_ORIGIN, "/v1/", options.path, options.query)
						: createApiUrl(ROUTES_ORIGIN, "/", options.path, options.query);

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
