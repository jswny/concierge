export const MAX_MCP_REQUEST_BODY_BYTES = 4 * 1024 * 1024;
// Match Code Mode's execution source limit before creating runtime state.
export const MAX_CODE_CHARS = 1_000_000;

export async function boundMcpRequest(request: Request): Promise<Request | Response> {
	if (request.method !== "POST" || !request.body) return request;
	if (Number(request.headers.get("Content-Length")) > MAX_MCP_REQUEST_BODY_BYTES) {
		await request.body.cancel().catch(() => undefined);
		return requestTooLarge();
	}

	const reader = request.body.getReader();
	const chunks: Uint8Array[] = [];
	let size = 0;
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			size += value.byteLength;
			if (size > MAX_MCP_REQUEST_BODY_BYTES) {
				await reader.cancel().catch(() => undefined);
				return requestTooLarge();
			}
			chunks.push(value);
		}
	} catch (error) {
		await reader.cancel().catch(() => undefined);
		throw error;
	} finally {
		reader.releaseLock();
	}

	const body = new Uint8Array(size);
	let offset = 0;
	for (const chunk of chunks) {
		body.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return new Request(request, { body });
}

function requestTooLarge() {
	return Response.json(
		{
			jsonrpc: "2.0",
			id: null,
			error: { code: -32000, message: `MCP request exceeds ${MAX_MCP_REQUEST_BODY_BYTES} bytes.` },
		},
		{ status: 413, headers: { "Access-Control-Allow-Origin": "*" } },
	);
}
