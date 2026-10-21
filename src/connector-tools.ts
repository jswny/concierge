import type { ConnectorTool, ToolExecuteContext } from "@cloudflare/codemode";
import type { z } from "zod";
import { toToolInputSchema } from "./connector-inputs";

export function defineConnectorTool<Schema extends z.ZodType, Result>(definition: {
	schema: Schema;
	description: string;
	outputSchema?: ConnectorTool["outputSchema"];
	replay?: ConnectorTool["replay"];
	execute(args: z.output<Schema>, context?: ToolExecuteContext): Result;
}): ConnectorTool {
	const { schema, execute, ...metadata } = definition;

	return {
		...metadata,
		inputSchema: toToolInputSchema(schema),
		execute: (args, context) => execute(schema.parse(args), context),
	};
}
