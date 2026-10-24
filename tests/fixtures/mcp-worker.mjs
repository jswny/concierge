import { boundMcpRequest } from "../../src/mcp-requests.ts";
import { observeCodeExecution } from "../../src/code-execution.ts";
import { UsageLog } from "../../src/usage-logging.ts";
import { ObservedConnector } from "../../src/observed-connector.ts";
import { tracing } from "cloudflare:workers";

class FixtureConnector extends ObservedConnector {
	constructor(ctx, env, usage, handler, metadata = {}) { super(ctx, env, usage); this.handler = handler; this.metadata = metadata; }
	name() { return "test"; }
	tools() { return { request: { ...this.metadata, execute: this.handler } }; }
}

export default {
	async fetch(request, env, ctx) {
		const options = await request.json();

		if (options.action === "unsupported-tool") {
			let calls = 0;
			const metadata = options.rollback ? { revert: () => {} } : { requiresApproval: options.requiresApproval };

			const connector = new FixtureConnector(ctx, env, new UsageLog(), () => { calls++;

 return null; }, metadata);

			try {
				if (options.describe) await connector.describe();
				else await connector.executeTool("request", {});

				return Response.json({ calls });
			} catch (error) {
				return Response.json({ error: error.message, calls });
			}
		}

		if (options.action === "ingress") {
			// Generate rejected uploads inside workerd, not over the harness's HTTP socket.
			const padding = (options.character ?? "x").repeat(options.count);

			const body = JSON.stringify(options.message
				? { ...options.message, params: { ...options.message.params, _meta: { padding } } }
				: { padding });

			const response = await env.CONCIERGE.fetch(new Request(`https://concierge.j1.io${options.path ?? "/debug/mcp"}`, {
				method: "POST",
				headers: { Host: "concierge.j1.io", "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
				body,
			}));

			return Response.json({
				status: response.status,
				headers: Object.fromEntries(response.headers),
				body: await response.text(),
				requestChars: body.length,
				requestBytes: new TextEncoder().encode(body).byteLength,
			});
		}

		if (options.action === "telemetry") {
			const logs = [];
			let executions = 0;
			const originalLog = console.log;
			const originalEnterSpan = tracing.enterSpan;
			const spans = [];

			if (options.mockTracing || options.tracingFailure) tracing.enterSpan = (name, callback) => {
				if (options.tracingFailure === "before") throw new Error("test tracing failure");
				const record = { name, attributes: {} };
				spans.push(record);

				const result = callback({
					setAttributes(attributes) { Object.assign(record.attributes, attributes); },
					setStatus(status) { record.status = status; },
				});

				if (options.tracingFailure === "after") throw new Error("test tracing failure");

				return result;
			};

			console.log = (message) => {
				if (options.loggingFailure) throw new Error("test logging failure");
				logs.push(JSON.parse(message));
			};

			try {
				const usage = new UsageLog();

				const result = await observeCodeExecution(async () => {
					executions++;

					if (options.throw) throw new Error("private exception must not be logged");

					for (const call of options.output.calls ?? []) {
						const connector = new FixtureConnector(ctx, env, usage, async () => {
							if (options.connectorThrow) throw new Error(options.connectorThrow);

							return call.result;
						});

						await connector.executeTool("request", call.args, { executionId: options.output.executionId });
					}

					return options.output;
				}, (output) => {
					if (options.formatThrow) throw new Error("output formatting failure");

					return options.response ?? output;
				}, usage);

				return Response.json({ result, sameReference: result === (options.response ?? options.output), logs, executions, spans });
			} catch (error) {
				return Response.json({ error: error instanceof Error ? error.message : String(error), logs, executions, spans });
			} finally {
				console.log = originalLog;
				tracing.enterSpan = originalEnterSpan;
			}
		}

		let cancelled = false;
		let chunksRead = 0;
		const headers = new Headers({ "X-Test-Header": "preserved" });

		if (options.contentLength !== undefined) headers.set("Content-Length", String(options.contentLength));

		const input = new Request("http://localhost/debug/mcp", {
			method: "POST",
			headers,
			body: new ReadableStream({
				pull(controller) {
					if (chunksRead === options.chunks.length) return controller.close();

					if (options.failAfterChunks === chunksRead) return controller.error(new Error("test body failure"));
					controller.enqueue(new Uint8Array(options.chunks[chunksRead++]));
				},
				cancel() { cancelled = true; },
			}, { highWaterMark: 0 }),
		});

		try {
			const result = await boundMcpRequest(input);

			if (result instanceof Response)
				return Response.json({ status: result.status, error: await result.json(), cancelled, chunksRead });

			return Response.json({
				status: 200,
				size: (await result.arrayBuffer()).byteLength,
				header: result.headers.get("X-Test-Header"),
				url: result.url,
				method: result.method,
				cancelled,
				chunksRead,
			});
		} catch (error) {
			return Response.json({ error: error.message });
		}
	},
};
