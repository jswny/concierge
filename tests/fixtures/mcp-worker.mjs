import { boundMcpRequest } from "../../src/mcp-requests.ts";
import { observeCodeExecution } from "../../src/code-execution.ts";

export default {
	async fetch(request, env) {
		const options = await request.json();
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
			console.log = (message) => {
				if (options.loggingFailure) throw new Error("test logging failure");
				logs.push(JSON.parse(message));
			};
			try {
				const result = await observeCodeExecution(async () => {
					executions++;
					if (options.throw) throw new Error("private exception must not be logged");
					return options.output;
				});
				return Response.json({ result, sameReference: result === options.output, logs, executions });
			} catch (error) {
				return Response.json({ error: error.message, logs, executions });
			} finally {
				console.log = originalLog;
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
