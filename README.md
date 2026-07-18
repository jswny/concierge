# Concierge MCP

Private Cloudflare-hosted MCP server for personal use.

Endpoint: `https://concierge.j1.io/mcp`

## Tool

- `code`: runs JavaScript in Cloudflare Code Mode against Concierge's typed upstream tools. Current upstream capability: `codemode.read_webpage_as_markdown({ url })`, which renders a public HTTP(S) URL with Cloudflare Browser Run, waits for `networkidle0`, and returns Markdown.
