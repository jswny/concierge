import { WorkerEntrypoint } from "cloudflare:workers";
const attempts = new Map();

export default class BrowserWorkerMock extends WorkerEntrypoint {
	async quickAction(action, options) {
		if (options.cacheTTL !== 0 || options.bestAttempt !== false || options.actionTimeout > 5_000 || options.gotoOptions.timeout > 30_000) throw new Error("Unexpected browser loading/cache policy");
		if (options.waitForSelector && (options.waitForSelector.visible !== true || options.waitForSelector.timeout > 10_000)) throw new Error("Unexpected selector policy");
		const meta = { title: "Mock webpage", finalUrl: "https://example.com/final", status: 200, headers: { "set-cookie": "private-test-cookie" } };
		if (options.url === "https://example.com/empty") return Response.json({ success: true, result: " \n", meta });
		if (options.url === "https://example.com/challenge") return Response.json({ success: true, result: "Enable JavaScript and cookies to continue", meta: { ...meta, title: "Just a moment..." } });
		if (options.url === "https://example.com/login") return Response.json({ success: true, result: "# Sign in", meta: { ...meta, title: "Sign in - Example" } });
		if (options.url === "https://example.com/gate-message") return Response.json({ success: true, result: "# Verify you are human\nChallenge", meta });
		if (options.url === "https://example.com/login-article") return Response.json({ success: true, result: "# Building a login page\nPlease sign in to continue is a common message.", meta });
		if (options.url === "https://example.com/not-found") return Response.json({ success: true, result: "Private upstream error", meta: { ...meta, status: 404 } });
		if (options.url === "https://example.com/long") return Response.json({ success: true, result: "0123456789".repeat(3_000), meta });
		if (options.url === "https://example.com/escaped") return Response.json({ success: true, result: "\t\"\\\n".repeat(4_000), meta });
		if (options.url === "https://example.com/oversized-metadata") return Response.json({ success: true, result: "Readable content", meta: { ...meta, finalUrl: "\u0000".repeat(4_000), title: "\u0000".repeat(1_000) } });
		if (options.url === "https://example.com/unicode") return Response.json({ success: true, result: "\uD83D\uDE00xyz", meta });
		if (options.url === "https://example.com/changing") {
			const count = (attempts.get(options.url) ?? 0) + 1;
			attempts.set(options.url, count);
			return Response.json({ success: true, result: `Version ${count}`, meta });
		}
		if (options.url === "https://example.com/reliability-invalid") return Response.json({ success: true, result: 123 });
		if (options.url === "https://example.com/reliability-retry") {
			const count = (attempts.get(options.url) ?? 0) + 1;
			attempts.set(options.url, count);
			if (count < 3) return new Response("temporary gateway failure", { status: 503 });
			return Response.json({ success: true, result: `# Retried ${count} times`, meta });
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
				`Selector: ${options.waitForSelector?.selector ?? "none"}`,
				`Selector timeout: ${options.waitForSelector?.timeout ?? "none"}`,
			].join("\n"),
			success: true,
			meta: options.url === "https://example.com/no-metadata" ? undefined : meta,
		});
	}
}
