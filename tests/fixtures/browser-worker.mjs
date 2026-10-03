import { WorkerEntrypoint } from "cloudflare:workers";
const attempts = new Map();

export default class BrowserWorkerMock extends WorkerEntrypoint {
	async quickAction(action, options) {
		if (options.url === "https://example.com/reliability-invalid") return Response.json({ success: true, result: 123 });
		if (options.url === "https://example.com/reliability-retry") {
			const count = (attempts.get(options.url) ?? 0) + 1;
			attempts.set(options.url, count);
			if (count < 3) return new Response("temporary gateway failure", { status: 503 });
			return Response.json({ success: true, result: `# Retried ${count} times` });
		}
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
