import { ConnectorRequests, createApiUrl, type ApiFailure, type ApiPayload, type RequestAuthentication } from "./connector-requests";
import type { HttpMethod, QueryValue } from "./connector-inputs";
import { RESPONSE_TYPES, type ResponseFormat, type JsonResponseFormat } from "./response-formats";
import type { JsonValue } from "./json";

type ApiRequest<Body> = {
	method: HttpMethod;
	path: string;
	query?: Record<string, QueryValue>;
	body?: Body;
};

type EncodedBody = { body: BodyInit | undefined; contentType: string };

type ApiService = { pathPrefix: string; paths?: ReadonlySet<string> };

export function selectApiService<Service extends ApiService>(path: string, services: readonly Service[]): Service {
	let selected: Service | undefined;

	for (const service of services) {
		if (!(service.paths ? service.paths.has(path) : path.startsWith(service.pathPrefix))) continue;

		if (selected) throw new Error("API path matches multiple enabled services.");
		selected = service;
	}

	if (!selected) throw new Error("API path does not match an enabled service.");

	return selected;
}

type ApiPolicy<Body> = {
	origin: string;
	pathPrefix: string;
	operation?: string;
	strictPaths?: boolean;
	readOnlyPostPaths?: ReadonlySet<string>;
	format?: ResponseFormat;
	validateUrl?(url: URL): void;
	encodeBody?(body: Body): EncodedBody;
	authenticate(context: { method: HttpMethod; url: URL }): RequestAuthentication | Promise<RequestAuthentication>;
	classifyError?: (status: number, payload: JsonValue | undefined) => ApiFailure;
	onResponse?(response: Response, headers: Headers): void;
};

/** Provider-bound REST mechanics; policies come from connector code, never tool arguments. */
export class ConnectorHttp {
	constructor(private readonly requests: ConnectorRequests, private readonly identity: { id: string; label: string }) {}

	request<Body>(options: ApiRequest<Body>, policy: ApiPolicy<Body> & { format?: JsonResponseFormat }): Promise<JsonValue>;
	request<Body>(options: ApiRequest<Body>, policy: ApiPolicy<Body>): Promise<ApiPayload>;
	request<Body>(options: ApiRequest<Body>, policy: ApiPolicy<Body>): Promise<ApiPayload> {
		const url = createApiUrl(policy.origin, policy.pathPrefix, options.path, options.query);

		if (policy.strictPaths && (/%25/i.test(options.path) || url.pathname.includes("//"))) {
			throw new Error(`${this.identity.label} paths cannot contain double encoding or empty path segments.`);
		}

		policy.validateUrl?.(url);

		const encoded = options.body === undefined ? undefined : policy.encodeBody
			? policy.encodeBody(options.body) : { body: JSON.stringify(options.body), contentType: RESPONSE_TYPES.json.mimeType };

		return this.requests.request({
			connector: this.identity.label,
			operation: policy.operation ?? "request",
			readOnly: options.method === "GET" || (options.method === "POST" && !!policy.readOnlyPostPaths?.has(url.pathname)),
			url,
			method: options.method,
			headers: encoded ? { "Content-Type": encoded.contentType } : undefined,
			body: encoded?.body,
			authenticate: () => policy.authenticate({ method: options.method, url }),
			classifyError: policy.classifyError,
			onResponse: policy.onResponse,
			format: policy.format,
		});
	}
}

export function encodeFormBody(values: Record<string, QueryValue>): EncodedBody {
	const body = new URLSearchParams();

	for (const [key, value] of Object.entries(values)) {
		for (const item of Array.isArray(value) ? value : [value]) body.append(key, String(item));
	}

	return { body, contentType: "application/x-www-form-urlencoded" };
}
