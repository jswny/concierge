import { CodemodeConnector, type ConnectorTool } from "@cloudflare/codemode";
import { annotate, traceOperation } from "./code-execution";
import { UsageLog } from "./usage-logging";

export abstract class ObservedConnector<E> extends CodemodeConnector<E> {
	constructor(ctx: DurableObjectState, env: E, private readonly usage: UsageLog) {
		super(ctx, env);
	}

	protected tool(name: string, tool: ConnectorTool): ConnectorTool {
		const original = super.tool(name, tool);
		return {
			...original,
			execute: (args, context) => traceOperation(`connector.${this.name()}.${name}`, async (span) => {
				if (context) this.usage.executionId = context.executionId;
				const startedAt = Date.now();
				const sequence = this.usage.nextSequence();
				let status: "success" | "error" = "error";
				annotate(span, {
					"concierge.invocation_id": this.usage.invocationId,
					"concierge.execution_id": context?.executionId,
					"concierge.connector": this.name(), "concierge.method": name,
				});
				try {
					const result = await original.execute(args, context);
					status = "success";
					return result;
				} finally {
					this.usage.connectorCall({
						connector: this.name(), method: name, sequence, status, durationMs: Date.now() - startedAt,
					});
					try { span?.setStatus({ code: status === "success" ? "ok" : "error" }); } catch {}
				}
			}),
		};
	}
}
