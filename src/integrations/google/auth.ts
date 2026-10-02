import { importPKCS8, SignJWT } from "jose";

const SERVICE_ACCOUNT = "concierge@j1-concierge.iam.gserviceaccount.com";
const WORKSPACE_USER = "joe@j1.io";
const TOKEN_LEEWAY_MS = 60_000;

type AccessToken = { value: string; expiresAt: number };

export class GoogleWorkspaceAuth {
	#tokens = new Map<string, AccessToken>();
	#pending = new Map<string, Promise<AccessToken>>();
	#credentials?: Promise<{ key: CryptoKey; kid: string }>;

	constructor(private readonly env: Env) {}

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
		const { key, kid } = await (this.#credentials ??= readCredentials(this.env.GOOGLE_SERVICE_ACCOUNT_JSON));
		const iat = Math.floor(Date.now() / 1000);
		const assertion = await new SignJWT({ sub: WORKSPACE_USER, scope })
			.setProtectedHeader({ alg: "RS256", typ: "JWT", kid })
			.setIssuer(SERVICE_ACCOUNT)
			.setAudience("https://oauth2.googleapis.com/token")
			.setIssuedAt(iat)
			.setExpirationTime(iat + 600)
			.sign(key);
		const delegated = await readAuthResponse(
			await fetch("https://oauth2.googleapis.com/token", {
				method: "POST",
				body: new URLSearchParams({
					grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
					assertion,
				}),
				redirect: "manual",
				signal: AbortSignal.timeout(20_000),
			}),
			"Workspace token exchange",
		);
		return readAccessToken(delegated, "Workspace token exchange", startedAt);
	}
}

async function readCredentials(value: string) {
	try {
		const data = JSON.parse(value);
		if (
			data?.type !== "service_account" || data.client_email !== SERVICE_ACCOUNT ||
			typeof data.private_key !== "string" || typeof data.private_key_id !== "string" || !data.private_key_id
		) throw new Error("Invalid service-account key.");
		return { key: await importPKCS8(data.private_key, "RS256"), kid: data.private_key_id };
	} catch {
		throw new Error("GOOGLE_SERVICE_ACCOUNT_JSON must contain a valid key for the Concierge service account.");
	}
}

async function readAuthResponse(response: Response, stage: string): Promise<Record<string, unknown>> {
	if (!response.ok) {
		// Never expose token-service bodies: they can contain credential material.
		await response.body?.cancel();
		throw new Error(`Google ${stage} returned HTTP ${response.status}.`);
	}
	let data: unknown;
	try {
		data = await response.json();
	} catch {
		throw new Error(`Google ${stage} returned invalid JSON.`);
	}
	if (!data || typeof data !== "object" || Array.isArray(data)) {
		throw new Error(`Google ${stage} returned an invalid response.`);
	}
	return data as Record<string, unknown>;
}

function readAccessToken(data: Record<string, unknown>, stage: string, startedAt = Date.now()): AccessToken {
	if (
		typeof data.access_token !== "string" || !data.access_token ||
		typeof data.expires_in !== "number" || !Number.isFinite(data.expires_in) ||
		data.expires_in <= TOKEN_LEEWAY_MS / 1000
	) {
		throw new Error(`Google ${stage} returned an invalid access token.`);
	}
	return {
		value: data.access_token,
		expiresAt: startedAt + Math.min(data.expires_in, 3600) * 1000,
	};
}
