import { importPKCS8, SignJWT } from "jose";
import { ConnectorError, ConnectorRequests } from "../../connector-requests";
import { z } from "zod";
import { parseJson } from "../../json";

const SERVICE_ACCOUNT = "concierge@j1-concierge.iam.gserviceaccount.com";
const WORKSPACE_USER = "joe@j1.io";
const TOKEN_LEEWAY_MS = 60_000;

type AccessToken = { value: string; expiresAt: number };

const credentialsSchema = z.object({
	type: z.literal("service_account"),
	client_email: z.literal(SERVICE_ACCOUNT),
	private_key: z.string(),
	private_key_id: z.string().min(1),
});

const tokenSchema = z.object({
	access_token: z.string().min(1),
	expires_in: z.number().gt(TOKEN_LEEWAY_MS / 1000),
});

export class GoogleWorkspaceAuth {
	#tokens = new Map<string, AccessToken>();
	#pending = new Map<string, Promise<AccessToken>>();
	#credentials?: Promise<{ key: CryptoKey; kid: string }>;

	constructor(private readonly env: Env, private readonly requests: ConnectorRequests) {}

	async accessToken(scopes: readonly string[]) {
		const key = [...scopes].sort().join(" ");
		const cached = this.#tokens.get(key);

		if (cached && cached.expiresAt > Date.now() + TOKEN_LEEWAY_MS) {
			return cached.value;
		}

		let pending = this.#pending.get(key);

		if (!pending) {
			pending = this.exchange(key)
				.then((token) => {
					this.#tokens.set(key, token);

					return token;
				})
				.finally(() => this.#pending.delete(key));
			this.#pending.set(key, pending);
		}

		return (await pending).value;
	}

	invalidate(value: string) {
		for (const [key, token] of this.#tokens) {
			if (token.value === value) this.#tokens.delete(key);
		}
	}

	private async exchange(scope: string): Promise<AccessToken> {
		const startedAt = Date.now();

		const delegated = await this.requests.request({
			connector: "Google authentication",
			operation: "Workspace token exchange",
			readOnly: true,
			timeoutMs: 20_000,
			url: new URL("https://oauth2.googleapis.com/token"),
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			sensitive: true,
			body: async () => {
				const { key, kid } = await (this.#credentials ??= readCredentials(this.env.GOOGLE_SERVICE_ACCOUNT_JSON));
				const iat = Math.floor(Date.now() / 1000);

				const assertion = await new SignJWT({ sub: WORKSPACE_USER, scope })
					.setProtectedHeader({ alg: "RS256", typ: "JWT", kid })
					.setIssuer(SERVICE_ACCOUNT)
					.setAudience("https://oauth2.googleapis.com/token")
					.setIssuedAt(iat)
					.setExpirationTime(iat + 600)
					.sign(key);

				return new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion });
			},
		});

		const token = tokenSchema.safeParse(delegated);

		if (!token.success) throw new ConnectorError({ category: "invalid_response", message: "Google Workspace token exchange returned an invalid access token." });

		return { value: token.data.access_token, expiresAt: startedAt + Math.min(token.data.expires_in, 3600) * 1000 };
	}
}

async function readCredentials(value: string) {
	try {
		const data = credentialsSchema.parse(parseJson(value));

		return { key: await importPKCS8(data.private_key, "RS256"), kid: data.private_key_id };
	} catch {
		throw new ConnectorError({ category: "configuration", message: "GOOGLE_SERVICE_ACCOUNT_JSON must contain a valid key for the Concierge service account." });
	}
}
