import { z } from "zod";
import type { ConnectorTool } from "@cloudflare/codemode";

export const apiScalarSchema = z.union([z.boolean(), z.number(), z.string()]);
export const httpMethodSchema = z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]);
export const apiQueryValueSchema = z.union([apiScalarSchema, z.array(apiScalarSchema)]);

export type HttpMethod = z.infer<typeof httpMethodSchema>;

export type QueryValue = z.infer<typeof apiQueryValueSchema>;

export function toToolInputSchema(schema: z.ZodType) {
	// SAFETY: The explicit draft-07 target restricts Zod's multi-dialect return type to Code Mode's accepted schema.
	return z.toJSONSchema(schema, { target: "draft-07" }) as NonNullable<ConnectorTool["inputSchema"]>;
}

export function apiRequestSchema<const Methods extends readonly [HttpMethod, ...HttpMethod[]]>(contract: {
	methods: Methods;
	pathPrefix: string;
	queryArrays?: boolean;
}) {
	return z.strictObject({
		method: z.enum(contract.methods).describe("API HTTP method."),
		path: z.string().startsWith(contract.pathPrefix)
			.describe(`Relative API path beginning with ${contract.pathPrefix}. Put query parameters in query.`),
		query: z.record(z.string(), contract.queryArrays ? apiQueryValueSchema : apiScalarSchema)
			.optional().describe(contract.queryArrays
				? "Optional query parameters. Arrays produce repeated parameters."
				: "Optional scalar query parameters."),
		body: z.unknown().optional().describe("Optional JSON request body documented for the endpoint."),
	}).superRefine((options, ctx) => {
		if (options.method === "GET" && options.body !== undefined) {
			ctx.addIssue({ code: "custom", path: ["body"], message: "GET requests cannot include a body." });
		}
	});
}
