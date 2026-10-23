import { cloudflareConnector } from "./cloudflare-connector";
import { googleConnector } from "./integrations/google/connector";
import { mapsConnector } from "./integrations/maps/connector";
import { unifiConnector } from "./integrations/unifi/connector";
import { twilioConnector } from "./integrations/twilio/connector";
import { exaConnector } from "./integrations/exa/connector";
import { kalshiConnector } from "./integrations/kalshi/connector";
import { fantasyprosConnector } from "./integrations/fantasypros/connector";
import type { ConnectorDependencies } from "./connector-definition";

export const CONNECTOR_DEFINITIONS = [
	cloudflareConnector, googleConnector, mapsConnector, unifiConnector, twilioConnector, exaConnector, kalshiConnector, fantasyprosConnector,
] as const;

export type ConnectorId = typeof CONNECTOR_DEFINITIONS[number]["id"];

export function createConnectors(dependencies: ConnectorDependencies) {
	return {
		connectors: CONNECTOR_DEFINITIONS.map((definition) => definition.create(dependencies)),
		connectorHints: Object.fromEntries<string>(CONNECTOR_DEFINITIONS.map((definition) => [definition.id, definition.hint])),
	};
}
