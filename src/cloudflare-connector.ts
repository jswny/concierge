import { CodemodeConnector, type ConnectorTools } from "@cloudflare/codemode";

type BrowserRunMarkdownResponse =
	| { result: string; success: true }
	| { errors?: Array<{ code?: number; detail?: string; message: string }>; success: false };

export class CloudflareConnector extends CodemodeConnector<Env> {
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
				inputSchema: {
					type: "object",
					properties: {
						url: {
							description: "The HTTP(S) webpage URL to render and convert to Markdown.",
							format: "uri",
							type: "string",
						},
					},
					required: ["url"],
					additionalProperties: false,
				},
				outputSchema: {
					type: "string",
				},
				replay: "reexecute",
				execute: async (args) => {
					const url = readUrlArg(args);
					return readWebpageAsMarkdown(this.env, url);
				},
			},
		};
	}
}

function readUrlArg(args: unknown) {
	if (!args || typeof args !== "object" || Array.isArray(args)) {
		throw new Error("Expected an object with a url string.");
	}

	const url = (args as { url?: unknown }).url;
	if (typeof url !== "string" || !url.trim()) {
		throw new Error("Expected url to be a non-empty string.");
	}

	return url;
}

async function readWebpageAsMarkdown(env: Env, url: string) {
	const parsedUrl = new URL(url);
	if (!["http:", "https:"].includes(parsedUrl.protocol)) {
		throw new Error("Only HTTP and HTTPS URLs are supported.");
	}

	const response = await env.BROWSER.quickAction("markdown", {
		url: parsedUrl.toString(),
		gotoOptions: {
			waitUntil: "networkidle0",
		},
	});
	const payload = (await response.json()) as BrowserRunMarkdownResponse;

	if (!response.ok || !payload.success) {
		const errors =
			payload.success === false && payload.errors?.length
				? payload.errors
						.map((error) =>
							[error.message, error.detail, error.code && `code ${error.code}`]
								.filter(Boolean)
								.join(" "),
						)
						.join("\n")
				: `Browser Run returned HTTP ${response.status}.`;

		throw new Error(errors);
	}

	return payload.result;
}
