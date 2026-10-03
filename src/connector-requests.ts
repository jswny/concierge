export type QueryValue = boolean | number | string | Array<boolean | number | string>;
type ErrorCategory =
	| "authentication"
	| "permission"
	| "configuration"
	| "rate_limited"
	| "http"
	| "network"
	| "timeout"
	| "invalid_response"
	| "response_too_large"
	| "busy";
type Outcome = "not_started" | "rejected" | "unknown" | "succeeded";
type FailureDetails = {
	category: ErrorCategory;
	message: string;
	retryable?: boolean;
	safeToReplay?: boolean;
	status?: number;
	code?: string;
	requestId?: string;
	retryAfterMs?: number;
	outcome?: Outcome;
	retryHandled?: boolean;
};

export class ConnectorError extends Error {
	constructor(readonly details: FailureDetails) {
		super(details.message);
		this.name = "ConnectorError";
	}
}

type Operation = {
	connector: string;
	operation: string;
	readOnly: boolean;
	safeToReplay?: boolean;
	timeoutMs?: number;
};
export type Attempt = {
	signal: AbortSignal;
	remainingMs(): number;
	dispatch(): void;
	succeeded(): void;
};
export type ApiFailure = {
	category?: ErrorCategory;
	message?: string;
	code?: string;
	requestId?: string;
	retryable?: boolean;
	safeToReplay?: boolean;
	outcome?: Outcome;
};
type ResponseOptions = Pick<HttpRequest, "format" | "sensitive" | "classifyError">;
type HttpRequest = Operation & {
	url: URL;
	method?: string;
	body?: BodyInit | (() => Promise<BodyInit>);
	headers?: HeadersInit | (() => Promise<HeadersInit>);
	format?: "json" | "json-or-text";
	sensitive?: boolean;
	classifyError?: (status: number, payload: unknown) => ApiFailure;
	onResponse?: (response: Response, headers: Headers) => void;
};
type Limits = {
	timeoutMs: number;
	maxRetries: number;
	concurrency: number;
	maxQueued: number;
	maxResponseBytes: number;
	backoffMs: number;
};
const DEFAULTS: Limits = {
	timeoutMs: 30_000,
	maxRetries: 2,
	concurrency: 4,
	maxQueued: 32,
	maxResponseBytes: 4 * 1024 * 1024,
	backoffMs: 250,
};

/** One instance per Concierge Durable Object; coordinates all calls to each provider. */
export class ConnectorRequests {
	private readonly limits: Limits;
	private readonly gates = new Map<string, Gate>();
	private readonly cooldowns = new Map<string, number>();

	constructor(limits: Partial<Limits> = {}) {
		this.limits = { ...DEFAULTS, ...limits };
	}

	async run<T>(operation: Operation, execute: (attempt: Attempt) => Promise<T>): Promise<T> {
		const startedAt = Date.now();
		const deadline = startedAt + (operation.timeoutMs ?? this.limits.timeoutMs);
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), Math.max(0, deadline - Date.now()));
		let attempts = 0;
		let outcome: Outcome = "not_started";
		let uncertainWrite = false;
		let release: (() => void) | undefined;
		let pending: Promise<T> | undefined;
		let failure: ConnectorError | undefined;
		try {
			let gate = this.gates.get(operation.connector);
			if (!gate) {
				gate = new Gate(this.limits.concurrency, this.limits.maxQueued);
				this.gates.set(operation.connector, gate);
			}
			release = await gate.acquire(controller.signal);
			for (;;) {
				let cooldown;
				while ((cooldown = (this.cooldowns.get(operation.connector) ?? 0) - Date.now()) > 0) {
					if (cooldown >= deadline - Date.now())
						throw new ConnectorError({
							category: "rate_limited",
							message: "Provider cooldown exceeds the operation deadline.",
							retryable: true,
							retryAfterMs: cooldown,
							outcome,
						});
					await wait(cooldown, controller.signal);
				}
				controller.signal.throwIfAborted();
				attempts++;
				outcome = "not_started";
				try {
					pending = execute({
						signal: controller.signal,
						remainingMs: () => Math.max(0, deadline - Date.now()),
						dispatch: () => {
							outcome = "unknown";
						},
						succeeded: () => {
							outcome = "succeeded";
						},
					});
					const result = await abortable(pending, controller.signal);
					failure = undefined;
					return result;
				} catch (error) {
					failure = normalizeError(error, controller.signal);
					if (outcome !== "not_started") outcome = failure.details.outcome ?? outcome;
					if (!operation.readOnly && outcome === "unknown") uncertainWrite = true;
					const retryAfterMs = failure.details.retryAfterMs;
					if (failure.details.category === "rate_limited" && retryAfterMs !== undefined) {
						this.cooldowns.set(
							operation.connector,
							Math.max(this.cooldowns.get(operation.connector) ?? 0, Date.now() + retryAfterMs),
						);
					}
					if (
						controller.signal.aborted ||
						failure.details.retryHandled ||
						!failure.details.retryable ||
						attempts > this.limits.maxRetries ||
						(!operation.readOnly && !operation.safeToReplay && !failure.details.safeToReplay)
					)
						throw failure;
					const delay = Math.max(
						retryAfterMs ?? 0,
						this.limits.backoffMs * 2 ** (attempts - 1) * (0.5 + Math.random()),
					);
					if (delay >= deadline - Date.now()) throw failure;
					await wait(delay, controller.signal);
				}
			}
		} catch (error) {
			failure = normalizeError(error, controller.signal);
			if (!operation.readOnly && uncertainWrite && outcome !== "succeeded") outcome = "unknown";
			const details = { ...failure.details, outcome, retryHandled: true };
			const context = [details.category, `attempts=${attempts}`];
			context.push(
				`retryable=${!!details.retryable}`,
				`safe_to_replay=${operation.readOnly || !!operation.safeToReplay || !!details.safeToReplay || outcome === "not_started"}`,
			);
			if (details.code) context.push(`code=${details.code}`);
			if (details.requestId) context.push(`request_id=${details.requestId}`);
			if (!operation.readOnly) context.push(`outcome=${details.outcome}`);
			const message = `${operation.connector} ${operation.operation}: ${details.message}${details.retryAfterMs !== undefined ? ` Retry-After: ${Math.ceil(details.retryAfterMs / 1000)}s.` : ""} [${context.join("; ")}]${!operation.readOnly && details.outcome === "unknown" ? " Write outcome is unknown; verify external state before retrying." : ""}`;
			throw new ConnectorError({ ...details, message });
		} finally {
			clearTimeout(timer);
			// A binding may not support cancellation. Keep its permit until it actually settles.
			if (controller.signal.aborted && pending) void pending.then(release, release);
			else release?.();
			console.log(
				JSON.stringify({
					event: "connector_request",
					connector: operation.connector,
					operation: operation.operation,
					durationMs: Date.now() - startedAt,
					attempts,
					category: failure?.details.category ?? "success",
					status: failure?.details.status,
					outcome: operation.readOnly ? undefined : outcome,
				}),
			);
		}
	}

	request(options: HttpRequest): Promise<unknown> {
		return this.run(options, async (attempt) => {
			const headers = new Headers(
				typeof options.headers === "function" ? await options.headers() : options.headers,
			);
			const body = typeof options.body === "function" ? await options.body() : options.body;
			headers.set("Accept", "application/json");
			if (options.body !== undefined && !headers.has("Content-Type"))
				headers.set("Content-Type", "application/json");
			attempt.signal.throwIfAborted();
			attempt.dispatch();
			const response = await fetch(options.url, {
				method: options.method ?? "GET",
				headers,
				body,
				redirect: "manual",
				signal: attempt.signal,
			});
			options.onResponse?.(response, headers);
			return this.responsePayload(response, attempt, options, headers);
		});
	}

	async responsePayload(
		response: Response,
		attempt: Attempt,
		options: ResponseOptions = {},
		headers = new Headers(),
	): Promise<unknown> {
		if (response.ok) attempt.succeeded();
		if (response.status === 401 || (!response.ok && options.sensitive)) {
			await response.body?.cancel();
			throw this.httpError(response, undefined, options, headers);
		}
		let payload: unknown;
		try {
			payload = await this.readPayload(
				response,
				attempt.signal,
				response.ok ? options.format : "json-or-text",
				response.ok ? undefined : 8192,
			);
		} catch (error) {
			if (response.ok || attempt.signal.aborted) throw error;
			// Non-JSON or oversized error bodies must not obscure the HTTP failure.
			payload = undefined;
		}
		if (!response.ok) throw this.httpError(response, payload, options, headers);
		return payload;
	}

	async readPayload(
		response: Response,
		signal: AbortSignal,
		format: "json" | "json-or-text" = "json",
		maxBytes = this.limits.maxResponseBytes,
	): Promise<unknown> {
		if (!response.body) return null;
		const reader = response.body.getReader();
		const chunks: Uint8Array[] = [];
		let size = 0;
		try {
			for (;;) {
				const { value, done } = await abortable(reader.read(), signal);
				if (done) break;
				size += value.byteLength;
				if (size > maxBytes)
					throw new ConnectorError({
						category: "response_too_large",
						message: `Response exceeds ${maxBytes} bytes; request a smaller result.`,
					});
				chunks.push(value);
			}
		} catch (error) {
			void reader.cancel().catch(() => {});
			throw error;
		} finally {
			reader.releaseLock();
		}
		const bytes = new Uint8Array(size);
		let offset = 0;
		for (const chunk of chunks) {
			bytes.set(chunk, offset);
			offset += chunk.byteLength;
		}
		const text = new TextDecoder().decode(bytes);
		if (!text) return null;
		try {
			return JSON.parse(text) as unknown;
		} catch {
			if (format === "json-or-text") return text;
			throw new ConnectorError({
				category: "invalid_response",
				message: "Upstream returned invalid JSON.",
			});
		}
	}

	httpError(
		response: Response,
		payload: unknown,
		options: Pick<HttpRequest, "classifyError" | "sensitive"> = {},
		headers = new Headers(),
	): ConnectorError {
		const status = response.status;
		const custom =
			options.sensitive || status === 401 ? {} : (options.classifyError?.(status, payload) ?? {});
		const category =
			custom.category ??
			(status === 401
				? "authentication"
				: status === 403
					? "permission"
					: status === 429
						? "rate_limited"
						: "http");
		const secrets = [
			headers.get("Authorization")?.replace(/^\S+\s+/, ""),
			headers.get("X-API-Key"),
		].filter((value): value is string => !!value);
		const message =
			category === "authentication" || category === "permission" || options.sensitive
				? ""
				: sanitize(custom.message, secrets);
		return new ConnectorError({
			category,
			message: `API returned HTTP ${status}.${message ? ` ${message}` : ""}`,
			status,
			code: sanitize(custom.code, secrets),
			requestId: sanitize(
				custom.requestId ??
					response.headers.get("X-Request-Id") ??
					response.headers.get("X-Goog-Request-Id") ??
					response.headers.get("CF-Ray") ??
					undefined,
				secrets,
			),
			retryable: custom.retryable ?? (status === 429 || [500, 502, 503, 504].includes(status)),
			safeToReplay: custom.safeToReplay ?? false,
			retryAfterMs: parseRetryAfter(response.headers.get("Retry-After")),
			outcome: custom.outcome ?? (status >= 500 || status < 400 ? "unknown" : "rejected"),
		});
	}
}

class Gate {
	private active = 0;
	private readonly queued: Array<{ enter(): void; reject(reason: unknown): void }> = [];
	constructor(
		private readonly capacity: number,
		private readonly maxQueued: number,
	) {}
	acquire(signal: AbortSignal): Promise<() => void> {
		signal.throwIfAborted();
		return new Promise((resolve, reject) => {
			const entry = {
				enter: () => {
					signal.removeEventListener("abort", cancel);
					this.active++;
					let released = false;
					resolve(() => {
						if (!released) {
							released = true;
							this.active--;
							this.queued.shift()?.enter();
						}
					});
				},
				reject,
			};
			const cancel = () => {
				const index = this.queued.indexOf(entry);
				if (index !== -1) this.queued.splice(index, 1);
				reject(signal.reason);
			};
			if (this.active < this.capacity) entry.enter();
			else if (this.queued.length >= this.maxQueued)
				reject(
					new ConnectorError({
						category: "busy",
						message: "Too many queued requests; use smaller batches.",
						retryable: true,
					}),
				);
			else {
				this.queued.push(entry);
				signal.addEventListener("abort", cancel, { once: true });
			}
		});
	}
}

export function createApiUrl(
	origin: string,
	prefix: string,
	path: string,
	query: Record<string, QueryValue> = {},
): URL {
	const url = new URL(path, origin);
	if (
		!path.startsWith(prefix) ||
		url.origin !== origin ||
		!url.pathname.startsWith(prefix) ||
		url.search ||
		url.hash ||
		url.username ||
		url.password ||
		/[\\\s]|%(?:2f|5c|2e)/i.test(path)
	)
		throw new Error(
			`API paths must stay under ${origin}${prefix} and put query parameters in query.`,
		);
	for (const [key, value] of Object.entries(query)) {
		if (["access_token", "oauth_token", "key", "token", "api_key"].includes(key.toLowerCase()))
			throw new Error("API credentials are managed server-side.");
		for (const item of Array.isArray(value) ? value : [value]) {
			if (!isScalar(item))
				throw new Error("Expected scalar query parameters or arrays of scalar values.");
			url.searchParams.append(key, String(item));
		}
	}
	return url;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
	return !!value && typeof value === "object" && !Array.isArray(value);
}
export function isScalar(value: unknown): value is boolean | number | string {
	return (
		typeof value === "boolean" ||
		typeof value === "string" ||
		(typeof value === "number" && Number.isFinite(value))
	);
}
export function parseRetryAfter(value: string | null, now = Date.now()): number | undefined {
	if (!value?.trim()) return undefined;
	if (/^\d+(?:\.\d+)?$/.test(value.trim())) {
		const ms = Number(value) * 1000;
		return Number.isFinite(ms) ? ms : undefined;
	}
	if (!/^[A-Za-z]{3}, \d{2} [A-Za-z]{3} \d{4} \d{2}:\d{2}:\d{2} GMT$/.test(value.trim()))
		return undefined;
	const timestamp = Date.parse(value);
	return Number.isFinite(timestamp) ? Math.max(0, timestamp - now) : undefined;
}
function sanitize(value: unknown, secrets: string[]): string | undefined {
	if (typeof value !== "string") return undefined;
	let text = value;
	for (const secret of secrets) text = text.replaceAll(secret, "[redacted]");
	return text.replace(/[\x00-\x1f\x7f]/g, " ").slice(0, 1000) || undefined;
}
function normalizeError(error: unknown, signal: AbortSignal): ConnectorError {
	if (signal.aborted)
		return new ConnectorError({
			category: "timeout",
			message: "Operation deadline exceeded.",
			retryable: true,
		});
	if (error instanceof ConnectorError) return error;
	return new ConnectorError({
		category: "network",
		message: "Upstream request failed.",
		retryable: true,
	});
}
function abortable<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
	if (signal.aborted) return Promise.reject(signal.reason);
	return new Promise((resolve, reject) => {
		const cancel = () => reject(signal.reason);
		signal.addEventListener("abort", cancel, { once: true });
		promise.then(resolve, reject).finally(() => signal.removeEventListener("abort", cancel));
	});
}
function wait(ms: number, signal: AbortSignal): Promise<void> {
	return new Promise((resolve, reject) => {
		signal.throwIfAborted();
		const timer = setTimeout(() => {
			signal.removeEventListener("abort", cancel);
			resolve();
		}, ms);
		const cancel = () => {
			clearTimeout(timer);
			reject(signal.reason);
		};
		signal.addEventListener("abort", cancel, { once: true });
	});
}
