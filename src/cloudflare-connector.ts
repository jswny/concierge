import { CodemodeConnector, type ConnectorTools } from "@cloudflare/codemode";
import { z } from "zod";
import { ConnectorError, ConnectorRequests, isRecord, type ApiFailure } from "./connector-requests";
import { toToolInputSchema } from "./connector-inputs";

const markdownSchema = z.strictObject({
	url: z.url().describe("The HTTP(S) webpage URL to render and convert to Markdown."),
});
const markdownInputSchema = toToolInputSchema(markdownSchema);

export class CloudflareConnector extends CodemodeConnector<Env> {
	constructor(ctx: DurableObjectState, env: Env, private readonly requests: ConnectorRequests) {
		super(ctx, env);
	}

	name() {
		return "cloudflare";
	}

	protected instructions() {
		return "Use for Cloudflare platform capabilities available to this personal concierge server.";
	}

	protected tools(): ConnectorTools {
		return {
			read_webpage_as_markdown: {
				description:
					"Read a public HTTP(S) webpage as Markdown. The page is rendered with Cloudflare Browser Run and waits for networkidle0 before extraction.",
				inputSchema: markdownInputSchema,
				outputSchema: {
					type: "string",
				},
				replay: "reexecute",
				execute: async (args) => {
					const { url } = markdownSchema.parse(args);
					const parsedUrl = new URL(url);
					if (!["http:", "https:"].includes(parsedUrl.protocol) || parsedUrl.username || parsedUrl.password) throw new Error("Only public HTTP and HTTPS URLs without credentials are supported.");
					return this.requests.run({ connector: "Cloudflare", operation: "read_webpage_as_markdown", readOnly: true, timeoutMs: 45_000 }, async (attempt) => {
						attempt.dispatch();
						const response = await this.env.BROWSER.quickAction("markdown", {
							url: parsedUrl.toString(),
							gotoOptions: { waitUntil: "networkidle0", timeout: Math.min(30_000, attempt.remainingMs()) },
						});
						const payload = await this.requests.responsePayload(response, attempt, { classifyError: classifyBrowserError });
						if (isRecord(payload) && payload.success === false) throw this.requests.httpError(response, payload, { classifyError: classifyBrowserError });
						if (!isRecord(payload) || payload.success !== true || typeof payload.result !== "string") throw new ConnectorError({ category: "invalid_response", message: "Browser Run returned an invalid Markdown response." });
						attempt.succeeded();
						return payload.result;
					});
				},
			},
		};
	}
}

function classifyBrowserError(_status: number, payload: unknown): ApiFailure {
	const error = isRecord(payload) && Array.isArray(payload.errors) && isRecord(payload.errors[0]) ? payload.errors[0] : {};
	return {
		message: typeof error.message === "string" ? error.message : undefined,
		code: typeof error.code === "number" ? String(error.code) : undefined,
	};
}
