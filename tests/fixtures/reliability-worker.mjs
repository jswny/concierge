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
import { RESPONSE_TYPES, responseAccept, supportedResponseTypes } from "../../src/response-formats.ts";

export default {
	async fetch(request) {
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
			if (options.action === "catalog") return Response.json(CONNECTOR_DEFINITIONS.map(({ id, label, hint }) => ({ id, label, hint })));

			if (options.action === "tool") {
				const tool = defineConnectorTool({
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
				const base = apiRequestSchema(options.contract);

				const schema = options.contract.extraKeys?.includes("service")
					? base.safeExtend({ service: z.enum(["gmail"]) }) : base;

				return Response.json({ result: schema.parse(options.args), inputSchema: toToolInputSchema(schema) });
			}

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
					url: new URL("https://reliability.example/api"),
					method: options.readOnly === false ? "POST" : "GET",
					authenticate: async () => {
						await new Promise((resolve) => setTimeout(resolve, options.prepareMs ?? 0));
						const secret = options.rotateAuth ? `fixture-secret-${++authentications}` : "fixture-secret";

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
