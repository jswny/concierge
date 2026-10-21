import { z } from "zod";
import { apiRequestSchema, apiQueryValueSchema, type QueryValue } from "../src/connector-inputs";
import { defineConnectorTool } from "../src/connector-tools";
import type { ConnectorId } from "../src/connectors";

type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2) ? true : false;

type Assert<T extends true> = T;

export type ConnectorIdsAreLiteral = Assert<Equal<ConnectorId, "cloudflare" | "google" | "maps" | "unifi" | "twilio" | "exa" | "kalshi">>;

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
