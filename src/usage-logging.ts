type ConnectorCall = {
	connector: string;
	method: string;
	sequence: number;
	status: "success" | "error";
	durationMs: number;
};

type ExecutionSummary = {
	durationMs: number;
	status: string;
	mcpStatus: string;
	connectorCalls: number;
};

/** Request-local operational metadata only; never accept source or API payloads. */
export class UsageLog {
	readonly invocationId = crypto.randomUUID();
	executionId?: string;
	private sequence = 0;

	get connectorCalls() { return this.sequence; }
	nextSequence() { return this.sequence++; }

	connectorCall(fields: ConnectorCall) {
		this.write("code_connector_call", fields);
	}

	summary(fields: ExecutionSummary) {
		this.write("code_execution", fields);
	}

	private write(event: string, fields: ConnectorCall | ExecutionSummary) {
		try {
			console.log(JSON.stringify({
				event, invocationId: this.invocationId, executionId: this.executionId, ...fields,
			}));
		} catch {}
	}
}
