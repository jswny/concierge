import {
	ConnectorRequests,
	ConnectorError,
	createApiUrl,
	parseRetryAfter,
} from "../../src/connector-requests.ts";
import { z } from "zod";
import { apiRequestSchema, toToolInputSchema } from "../../src/connector-inputs.ts";
import { defineConnectorTool } from "../../src/connector-tools.ts";
import { CONNECTOR_DEFINITIONS } from "../../src/connectors.ts";
import { ConnectorHttp, encodeFormBody, selectApiService } from "../../src/connector-http.ts";
import { ConnectorImages } from "../../src/connector-images.ts";
import { GoogleWorkspaceAuth } from "../../src/integrations/google/auth.ts";
import { UsageLog } from "../../src/usage-logging.ts";
import { JPEG_BASE64 } from "./jpeg.mjs";
import { RESPONSE_TYPES, responseAccept, supportedResponseTypes } from "../../src/response-formats.ts";

export default {
	async fetch(request, env, ctx) {
		const options = await request.json();
		const runtime = new ConnectorRequests({ timeoutMs: 500, backoffMs: 1, ...options.limits });

		const operation = {
			connector: "test",
			operation: "operation",
			readOnly: options.readOnly ?? true,
			safeToReplay: options.replaySafe,
		};

		let attempts = 0;
		let active = 0;
		let peak = 0;
		let cancelled = false;
		let failuresRemaining = options.failuresBeforeSuccess ?? Infinity;
		const dispatchTimes = [];
		const pendingWork = [];
		const originalLog = console.log;

		if (options.loggingFailure) console.log = () => { throw new Error("test logging failure"); };

		try {
			if (options.action === "rest") {
				const http = new ConnectorHttp(runtime, { id: "test", label: "Test API" });

				const result = await http.request(options.args, {
					origin: "https://reliability.example", pathPrefix: "/api/", strictPaths: true,
					readOnlyPostPaths: new Set(["/api/search"]),
					validateUrl: (url) => {
						if (url.pathname === "/api/blocked") throw new Error("Provider restriction.");
					},
					encodeBody: options.form ? encodeFormBody : undefined,
					authenticate: () => ({ headers: { "X-Test-Credential": "fixture-secret" }, sensitiveValues: ["fixture-secret"] }),
				});

				return Response.json({ result });
			}

			if (options.action === "catalog") {
				const dependencies = { ctx, env, requests: runtime, images: new ConnectorImages(), googleAuth: new GoogleWorkspaceAuth(env, runtime), usage: new UsageLog() };

				const catalog = await Promise.all(CONNECTOR_DEFINITIONS.map(async (definition) => ({
					id: definition.id, label: definition.label, hint: definition.hint, description: await definition.create(dependencies).describe(),
				})));

				return Response.json(catalog);
			}

			if (options.action === "tool-image") {
				const images = new ConnectorImages();
				const bytes = Uint8Array.from(atob(JPEG_BASE64), (char) => char.charCodeAt(0));

				const tool = defineConnectorTool({
					schema: z.strictObject({}), description: "Test shared image capture.",
					images: options.noStore ? undefined : images,
					execute: () => ({ type: "image", mimeType: "image/jpeg", data: bytes }),
				});

				const result = await tool.execute({}, options.noContext ? undefined : { executionId: "test-execution" });

				return Response.json({ result, resolvedByteLength: images.resolve("test-execution", result).data.byteLength });
			}

			if (options.action === "tool") {
				const tool = defineConnectorTool({
					...options.metadata,
					description: "Test inferred and validated tool arguments.",
					schema: z.strictObject({ name: z.string().trim(), count: z.number().default(2) }),
					execute: (args, context) => ({ ...args, executionId: context?.executionId }),
				});

				return Response.json({ result: await tool.execute(options.args, { executionId: "test-execution" }), inputSchema: tool.inputSchema });
			}

			if (options.action === "formats") return Response.json({
				types: Object.values(RESPONSE_TYPES).map(({ kind, mimeType }) => ({ kind, mimeType })),
				accept: responseAccept(options.format),
				description: supportedResponseTypes(options.format ?? "json"),
			});

			if (options.action === "inputs") {
				const schema = apiRequestSchema(options.contract);

				return Response.json({ result: schema.parse(options.args), inputSchema: toToolInputSchema(schema) });
			}

			if (options.action === "service") return Response.json(selectApiService(options.path, options.services));

			if (options.action === "retry-after")
				return Response.json(options.values.map((value) => parseRetryAfter(value, 0) ?? null));

			if (options.action === "url")
				return Response.json({
					url: createApiUrl("https://example.com", "/api/", options.path, options.query).href,
				});

			if (options.action === "request") {
				let authentications = 0;

				const result = await runtime.request({
					...operation,
					url: new URL(options.requestPath ?? "/api", "https://reliability.example"),
					method: options.readOnly === false ? "POST" : "GET",
					sensitive: options.sensitive,
					authenticate: async () => {
						await new Promise((resolve) => setTimeout(resolve, options.prepareMs ?? 0));
						const secret = options.rotateAuth ? `fixture-secret-${++authentications}` : (options.secret ?? "fixture-secret");

						return {
							headers: options.rotateAuth ? { "X-Test-Credential": secret } : { Authorization: `Bearer ${secret}` },
							sensitiveValues: [secret],
						};
					},
					classifyError: (_status, payload) => ({ message: payload?.message, code: payload?.code }),
					format: options.format,
				});

				return Response.json({ result });
			}

			const results = await Promise.allSettled(
				Array.from({ length: options.count ?? 1 }, () =>
					runtime.run(operation, async (attempt) => {
						let settled;
						pendingWork.push(new Promise((resolve) => { settled = resolve; }));
						attempts++;
						active++;
						peak = Math.max(peak, active);

						try {
							if (options.failPreparationAfterFirst && attempts > 1)
								throw new ConnectorError({
									category: "configuration",
									message: "Preparation failed.",
								});
							attempt.dispatch();
							dispatchTimes.push(Date.now());

							if (options.action === "body") {
								attempt.succeeded();

								const response = new Response(
									new ReadableStream({
										start(controller) {
											controller.enqueue(options.bodyBase64
												? Uint8Array.from(atob(options.bodyBase64), (char) => char.charCodeAt(0))
												: new TextEncoder().encode(options.body ?? "{}"));

											if (options.closeBody) controller.close();
										},
										cancel() {
											cancelled = true;
										},
									}),
									{ headers: options.headers },
								);

								return await runtime.readPayload(response, attempt.signal, options.format);
							}

							await new Promise((resolve) => setTimeout(resolve, options.delayMs ?? 5));

							if (options.failureRaw) throw new Error("fixture-secret must not escape");

							if (options.failure && failuresRemaining-- > 0)
								throw new ConnectorError(options.failure);
							attempt.succeeded();

							return "ok";
						} finally {
							active--;
							settled();
						}
					}),
				),
			);

			await Promise.all(pendingWork);

			return Response.json({
				attempts,
				peak,
				active,
				cancelled,
				dispatchTimes,
				results: results.map((result) =>
					result.status === "fulfilled"
						? { result: result.value }
						: { error: result.reason.message, details: result.reason.details },
				),
			});
		} catch (error) {
			return Response.json({ error: error.message, details: error.details });
		} finally {
			console.log = originalLog;
		}
	},
};
