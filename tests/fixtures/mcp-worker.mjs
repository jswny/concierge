import { boundMcpRequest } from "../../src/mcp-requests.ts";

export default {
	async fetch(request) {
		const options = await request.json();
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
