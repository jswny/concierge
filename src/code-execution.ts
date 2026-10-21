import type { ProxyToolOutput } from "@cloudflare/codemode";
import { tracing } from "cloudflare:workers";
import { UsageLog } from "./usage-logging";

export async function observeCodeExecution<T extends { isError?: boolean }>(
	execute: () => Promise<ProxyToolOutput>,
	format: (output: ProxyToolOutput) => T,
	log = new UsageLog(),
): Promise<T> {
	const run = async (span?: Span) => {
		const startedAt = Date.now();
		let status: ProxyToolOutput["status"] | "exception" = "exception";
		let mcpStatus = "exception";
		annotate(span, { "concierge.invocation_id": log.invocationId });

		try {
			const output = await execute();
			log.executionId = output.executionId;
			status = output.status;
			const response = format(output);
			mcpStatus = response.isError || status !== "completed" ? "error" : "success";

			return response;
		} finally {
			annotate(span, {
				"concierge.execution_id": log.executionId, "concierge.runtime_status": status,
				"concierge.mcp_status": mcpStatus, "concierge.connector_calls": log.connectorCalls,
			});

			try { span?.setStatus({ code: mcpStatus === "success" ? "ok" : "error" }); } catch {}

			log.summary({ durationMs: Date.now() - startedAt, status, mcpStatus, connectorCalls: log.connectorCalls });
		}
	};

	return traceOperation("mcp.code", run);
}

export async function traceOperation<T>(name: string, run: (span?: Span) => Promise<T>): Promise<T> {
	// If instrumentation fails, await the same work; never run code twice or mask its exception.
	let pending: Promise<T> | undefined;

	try {
		return await tracing.enterSpan(name, (span) => pending = run(span));
	} catch {
		return pending ?? run();
	}
}

export function annotate(span: Span | undefined, attributes: Record<string, string | number | undefined>) {
	try { span?.setAttributes(attributes); } catch {}
}
