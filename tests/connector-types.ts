import { z } from "zod";
import { apiRequestSchema, apiQueryValueSchema, type QueryValue } from "../src/connector-inputs";

type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2) ? true : false;

type Assert<T extends true> = T;

const limitedRequest = apiRequestSchema({ methods: ["GET", "POST"], pathPrefix: "/" });

export type MethodLiteralsArePreserved = Assert<Equal<z.infer<typeof limitedRequest>["method"], "GET" | "POST">>;

export type QueryValuesFollowTheSchema = Assert<Equal<QueryValue, z.infer<typeof apiQueryValueSchema>>>;

// @ts-expect-error Unsupported HTTP methods must fail at the authoring boundary.
apiRequestSchema({ methods: ["TRACE"], pathPrefix: "/" });
