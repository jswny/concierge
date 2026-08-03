import { WorkerEntrypoint } from "cloudflare:workers";

export default class BrowserWorkerMock extends WorkerEntrypoint {
	async quickAction(action, options) {
		if (action !== "markdown") {
			return Response.json(
				{
					errors: [{ message: `Unexpected Browser Run action: ${action}` }],
					success: false,
				},
				{ status: 400 },
			);
		}

		return Response.json({
			result: [
				"# Mock webpage",
				`URL: ${options.url}`,
				`Wait: ${options.gotoOptions?.waitUntil ?? "none"}`,
			].join("\n"),
			success: true,
		});
	}
}
