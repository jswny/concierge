import type { ProxyToolOutput } from "@cloudflare/codemode";

export async function observeCodeExecution(execute: () => Promise<ProxyToolOutput>): Promise<ProxyToolOutput> {
	const startedAt = Date.now();
	let status: ProxyToolOutput["status"] | "exception" = "exception";
	let connectorCalls: number | undefined;
	try {
		const output = await execute();
		status = output.status;
		connectorCalls = output.calls?.length;
		return output;
	} finally {
		// Observability must never change the execution outcome.
		try {
			console.log(JSON.stringify({
				event: "code_execution",
				durationMs: Date.now() - startedAt,
				status,
				connectorCalls,
			}));
		} catch {}
	}
}
