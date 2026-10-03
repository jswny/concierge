import { z } from "zod";
import type { ConnectorTool } from "@cloudflare/codemode";

const scalar = z.union([z.boolean(), z.number(), z.string()]);

export function toToolInputSchema(schema: z.ZodType) {
	// Zod's return type spans multiple dialects; Code Mode accepts Draft 7 specifically.
	return z.toJSONSchema(schema, { target: "draft-07" }) as NonNullable<ConnectorTool["inputSchema"]>;
}

export function apiRequestSchema(contract: {
	methods: readonly [string, ...string[]];
	pathPrefix: string;
	queryArrays?: boolean;
}) {
	return z.strictObject({
		method: z.enum(contract.methods).describe("API HTTP method."),
		path: z.string().startsWith(contract.pathPrefix)
			.describe(`Relative API path beginning with ${contract.pathPrefix}. Put query parameters in query.`),
		query: z.record(z.string(), contract.queryArrays ? z.union([scalar, z.array(scalar)]) : scalar)
			.optional().describe(contract.queryArrays
				? "Optional query parameters. Arrays produce repeated parameters."
				: "Optional scalar query parameters."),
		body: z.unknown().optional().describe("Optional JSON request body documented for the endpoint."),
	});
}

export function parseApiRequest<T extends { method: string; body?: unknown }>(schema: z.ZodType<T>, args: unknown): T {
	const options = schema.parse(args);
	if (options.method === "GET" && options.body !== undefined) {
		throw new Error("GET requests cannot include a body.");
	}
	return options;
}
