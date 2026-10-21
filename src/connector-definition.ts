import type { ObservedConnector } from "./observed-connector";
import type { ConnectorRequests } from "./connector-requests";
import type { ConnectorImages } from "./connector-images";
import type { GoogleWorkspaceAuth } from "./integrations/google/auth";
import type { UsageLog } from "./usage-logging";

export type ConnectorDependencies = {
	ctx: DurableObjectState;
	env: Env;
	requests: ConnectorRequests;
	images: ConnectorImages;
	googleAuth: GoogleWorkspaceAuth;
	usage: UsageLog;
};

export function defineConnector<const Id extends string>(definition: {
	id: Id;
	label: string;
	hint: string;
	create(dependencies: ConnectorDependencies): ObservedConnector<Env>;
}) {
	return definition;
}
