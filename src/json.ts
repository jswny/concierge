import { z } from "zod";

export type JsonValue = null | boolean | number | string | JsonValue[] | JsonObject;

export type JsonObject = { [key: string]: JsonValue | undefined };

const objectSchema = z.object({});

/** Discriminate an already parsed JSON union without copying or revalidating its children. */
export function isJsonObject(value: JsonValue | undefined): value is JsonObject {
	return objectSchema.safeParse(value).success;
}

export function parseJson(text: string): JsonValue {
	// SAFETY: Native JSON.parse without a reviver produces only JSON primitives, arrays and objects.
	return JSON.parse(text) as JsonValue;
}
