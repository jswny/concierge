import { DurableObject } from "cloudflare:workers";
import { McpEvents } from "../../src/mcp-events/service.ts";
import { subscribeParams, unsubscribeParams } from "../../src/mcp-events/protocol.ts";
import { twilioMessageEvents, MESSAGE_EVENT } from "../../src/integrations/twilio/events.ts";

// Test-only storage/clock controls. Never exported from the production Worker.
export class EventFixture extends DurableObject {
	authorized = true;
	service() { return new McpEvents(this.ctx, "fixture-encryption-key", [twilioMessageEvents], async () => this.authorized); }
	async run(input) {
		const owner = { userId: "owner", clientId: "client", grantId: "grant", expiresAt: Date.now() + 3600_000, ...input.owner };
		const service = this.service();
		if (input.action === "subscribe") return service.subscribe(subscribeParams.parse(input.params), owner);
		if (input.action === "unsubscribe") return service.unsubscribe(unsubscribeParams.parse(input.params), owner);
		if (input.action === "publish") { await service.publish(MESSAGE_EVENT, input.message.MessageSid, input.message); return {}; }
		if (input.action === "expire") this.ctx.storage.sql.exec("UPDATE mcp_event_subscriptions SET expires = 0");
		if (input.action === "revoke") this.authorized = false;
		if (input.action === "deliver") {
			this.ctx.storage.sql.exec("UPDATE mcp_event_deliveries SET next_attempt = 0");
			await service.alarm();
		}
		return {
			subscriptions: this.ctx.storage.sql.exec("SELECT * FROM mcp_event_subscriptions").toArray(),
			jobs: this.ctx.storage.sql.exec("SELECT * FROM mcp_event_deliveries").toArray(),
			receipts: this.ctx.storage.sql.exec("SELECT * FROM mcp_event_receipts").toArray(),
		};
	}
	alarm() { return this.service().alarm(); }
}

export default {
	async fetch(request, env) {
		const input = await request.json();
		try { return Response.json(await env.EVENTS.getByName(input.instance ?? "default").run(input)); }
		catch (error) { return Response.json({ error: error.message, code: error.code }); }
	},
};
