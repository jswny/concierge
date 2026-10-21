import type { ConnectorTool, ToolExecuteContext } from "@cloudflare/codemode";
import type { z } from "zod";
import { toToolInputSchema } from "./connector-inputs";
import { ConnectorImages, isConnectorImage } from "./connector-images";

export type ConciergeTool = Omit<ConnectorTool, "requiresApproval" | "revert"> & {
	requiresApproval?: never;
	revert?: never;
};

export type ConciergeTools = Record<string, ConciergeTool>;

export function assertSupportedTool(tool: Pick<ConnectorTool, "requiresApproval" | "revert">): void {
	if (tool.requiresApproval !== undefined || tool.revert !== undefined) {
		throw new Error("Code Mode approvals and rollback handlers are not supported by Concierge.");
	}
}

export function defineConnectorTool<Schema extends z.ZodType, Result>(definition: {
	schema: Schema;
	description: string;
	outputSchema?: ConnectorTool["outputSchema"];
	replay?: ConnectorTool["replay"];
	requiresApproval?: never;
	revert?: never;
	images?: ConnectorImages;
	execute(args: z.output<Schema>, context?: ToolExecuteContext): Result;
}): ConciergeTool {
	assertSupportedTool(definition);
	const { schema, execute, images, ...metadata } = definition;

	return {
		...metadata,
		inputSchema: toToolInputSchema(schema),
		execute: async (args, context) => {
			const result = await execute(schema.parse(args), context);

			if (!isConnectorImage(result)) return result;

			if (!images) throw new Error("Image-returning tools require an invocation-local image store.");

			if (!context) throw new Error("Image retrieval requires a Code Mode invocation.");

			return images.capture(context.executionId, result);
		},
	};
}
