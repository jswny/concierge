import type { ConsentDescription } from "@cloudflare/workers-oauth-provider";

function escapeHtml(value: string) {
	return value.replace(/[&<>"']/g, (char) => `&#${char.charCodeAt(0)};`);
}

export function renderConsentPage(details: ConsentDescription, handle: string) {
	const clientName = escapeHtml(details.clientName);
	const publisher = details.clientDomain
		? `<p>Published by <strong>${escapeHtml(details.clientDomain)}</strong></p>`
		: "";
	const scopes = details.scope.length
		? `<dt>Permissions</dt><dd>${details.scope.map(escapeHtml).join(", ")}</dd>`
		: "<dt>Permissions</dt><dd>Access to Concierge tools</dd>";
	return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${clientName} | Concierge Authorization</title>
  <style>
    * { box-sizing: border-box; }
    body { margin: 0; background: #f9fafb; color: #333; font: 16px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    main { width: min(100% - 32px, 600px); margin: 48px auto; }
    header { display: flex; align-items: center; justify-content: center; gap: 16px; margin-bottom: 32px; }
    header img { width: 48px; height: 48px; border-radius: 8px; }
    header span { font-size: 20px; }
    section { padding: 32px; border: 1px solid #e5e7eb; border-radius: 8px; background: #fff; }
    h1 { margin: 0 0 16px; font-size: 24px; line-height: 1.35; overflow-wrap: anywhere; }
    p, dd { overflow-wrap: anywhere; }
    dt { color: #555; font-size: 14px; margin-top: 16px; }
    dd { margin: 0; }
    .warning { padding-left: 12px; border-left: 3px solid #c2410c; }
    form { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 12px; margin-top: 32px; }
    button { min-height: 44px; padding: 10px 20px; border: 1px solid #d1d5db; border-radius: 6px; background: #fff; color: #333; font: inherit; cursor: pointer; }
    button[value="approve"] { background: #0070f3; border-color: #0070f3; color: #fff; }
    button:focus-visible { outline: 3px solid #0070f3; outline-offset: 3px; }
    @media (max-width: 480px) { main { margin: 24px auto; } section { padding: 24px; } }
  </style>
</head>
<body>
  <main>
    <header><img src="https://avatars.githubusercontent.com/u/314135?s=200&v=4" alt=""><span>Concierge MCP</span></header>
    <section>
      <h1>Allow ${clientName} to access Concierge?</h1>
      ${publisher}
      <dl>
        <dt>Access will be sent to</dt><dd><strong>${escapeHtml(details.redirectHost)}</strong></dd>
        ${scopes}
      </dl>
      ${details.redirectIsLoopback ? '<p class="warning">This sends access to an app on your computer. Continue only if you just started signing in from it.</p>' : ""}
      <p>Continue to sign in with Cloudflare Access.</p>
      <form method="post" action="/authorize">
        <input type="hidden" name="handle" value="${escapeHtml(handle)}">
        <button name="decision" value="deny">Deny</button>
        <button name="decision" value="approve">Approve</button>
      </form>
    </section>
  </main>
</body>
</html>`;
}
