import { isRecord, isScalar, type QueryValue } from "./connector-requests";

export type ApiRequestArgs = {
	method: string;
	path: string;
	query?: Record<string, QueryValue>;
	body?: unknown;
};

type ApiRequestContract = {
	methods: readonly string[];
	pathPrefix: string;
	queryArrays?: boolean;
	extraKeys?: readonly string[];
};

export function readApiRequestArgs(args: unknown, contract: ApiRequestContract): ApiRequestArgs {
	const keys = ["method", "path", "query", "body", ...(contract.extraKeys ?? [])];
	if (!isRecord(args) || Object.keys(args).some((key) => !keys.includes(key))) {
		throw new Error("Expected an API request with only the documented fields.");
	}
	const { method, path, query, body } = args;
	if (typeof method !== "string" || !contract.methods.includes(method)) {
		throw new Error(`Expected method to be one of: ${contract.methods.join(", ")}.`);
	}
	if (typeof path !== "string" || !path.startsWith(contract.pathPrefix)) {
		throw new Error(`Expected path to begin with ${contract.pathPrefix}.`);
	}
	if (
		query !== undefined &&
		(!isRecord(query) || Object.values(query).some((value) =>
			!(contract.queryArrays && Array.isArray(value) ? value.every(isScalar) : isScalar(value)),
		))
	) {
		throw new Error(
			`Expected query parameters to be finite scalar values${contract.queryArrays ? " or arrays of scalar values" : ""}.`,
		);
	}
	if (method === "GET" && body !== undefined) {
		throw new Error("GET requests cannot include a body.");
	}
	return { method, path, query: query as ApiRequestArgs["query"], body };
}
