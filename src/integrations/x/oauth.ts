export const X_OAUTH_CALLBACK_PATH = "/integrations/x/callback";

const X_AUTHORIZATION_URL = "https://x.com/i/oauth2/authorize";
const X_TOKEN_URL = "https://api.x.com/2/oauth2/token";
const X_TOKEN_STORAGE_KEY = "x:oauth:tokens";
const X_ACTIVE_STATE_STORAGE_KEY = "x:oauth:active-state";
const X_PENDING_STATE_STORAGE_PREFIX = "x:oauth:pending:";
const X_AUTHORIZATION_TTL_MS = 10 * 60 * 1000;
const X_REFRESH_LEEWAY_MS = 60 * 1000;
const X_OAUTH_SCOPES = [
	"block.read",
	"block.write",
	"bookmark.read",
	"bookmark.write",
	"dm.read",
	"dm.write",
	"follows.read",
	"follows.write",
	"like.read",
	"like.write",
	"list.read",
	"list.write",
	"media.write",
	"mute.read",
	"mute.write",
	"offline.access",
	"space.read",
	"timeline.read",
	"tweet.moderate.write",
	"tweet.read",
	"tweet.write",
	"users.email",
	"users.read",
];

type XOAuthTokenRecord = {
	accessToken: string;
	expiresAt: number;
	refreshToken: string;
	scopes: string[];
};

type XPendingAuthorization = {
	codeVerifier: string;
	expiresAt: number;
	redirectUri: string;
	scopes: string[];
};

type XTokenResponse = {
	access_token?: unknown;
	expires_in?: unknown;
	refresh_token?: unknown;
	scope?: unknown;
	token_type?: unknown;
};

export class XOAuthManager {
	private refreshInFlight?: Promise<XOAuthTokenRecord>;

	constructor(
		private readonly state: DurableObjectState,
		private readonly env: Env,
	) {}

	async beginAuthorization() {
		this.requireClientCredentials();

		const normalizedScopes = [...X_OAUTH_SCOPES].sort();
		const state = randomBase64Url(32);
		const codeVerifier = randomBase64Url(64);
		const codeChallenge = await createCodeChallenge(codeVerifier);
		const redirectUri = `https://concierge.j1.io${X_OAUTH_CALLBACK_PATH}`;
		const expiresAt = Date.now() + X_AUTHORIZATION_TTL_MS;
		const pending: XPendingAuthorization = {
			codeVerifier,
			expiresAt,
			redirectUri,
			scopes: normalizedScopes,
		};
		const previousState = await this.state.storage.get<string>(X_ACTIVE_STATE_STORAGE_KEY);

		await Promise.all([
			this.state.storage.put(X_ACTIVE_STATE_STORAGE_KEY, state),
			this.state.storage.put(`${X_PENDING_STATE_STORAGE_PREFIX}${state}`, pending),
			previousState
				? this.state.storage.delete(`${X_PENDING_STATE_STORAGE_PREFIX}${previousState}`)
				: Promise.resolve(false),
		]);

		const authorizationUrl = new URL(X_AUTHORIZATION_URL);
		authorizationUrl.searchParams.set("response_type", "code");
		authorizationUrl.searchParams.set("client_id", this.env.X_CLIENT_ID);
		authorizationUrl.searchParams.set("redirect_uri", redirectUri);
		authorizationUrl.searchParams.set("scope", normalizedScopes.join(" "));
		authorizationUrl.searchParams.set("state", state);
		authorizationUrl.searchParams.set("code_challenge", codeChallenge);
		authorizationUrl.searchParams.set("code_challenge_method", "S256");

		return {
			authorizationUrl: authorizationUrl.href,
			expiresAt: new Date(expiresAt).toISOString(),
		};
	}

	async authorizationStatus() {
		const tokens = await this.readTokens();
		if (!tokens) {
			return {
				connected: false,
				expiresAt: null,
				scopes: [],
			};
		}

		return {
			connected: true,
			expiresAt: new Date(tokens.expiresAt).toISOString(),
			scopes: tokens.scopes,
		};
	}

	async getUserAccessToken() {
		const tokens = await this.readTokens();
		if (!tokens) {
			return null;
		}

		if (tokens.expiresAt > Date.now() + X_REFRESH_LEEWAY_MS) {
			return tokens.accessToken;
		}

		const refreshed = await this.refreshTokens(tokens);
		return refreshed.accessToken;
	}

	async handleCallback(request: Request) {
		if (request.method !== "GET") {
			return callbackResponse("Method not allowed", 405);
		}

		const url = new URL(request.url);
		const state = url.searchParams.get("state");
		const code = url.searchParams.get("code");
		const oauthError = url.searchParams.get("error");
		if (!state) {
			return callbackResponse("Missing X OAuth state.", 400);
		}
		if (!/^[A-Za-z0-9_-]{43}$/.test(state)) {
			return callbackResponse("Invalid or expired X OAuth state.", 400);
		}

		const pendingKey = `${X_PENDING_STATE_STORAGE_PREFIX}${state}`;
		const pending = await this.state.storage.get<XPendingAuthorization>(pendingKey);
		if (!pending || pending.expiresAt <= Date.now()) {
			await this.state.storage.delete(pendingKey);
			return callbackResponse("Invalid or expired X OAuth state.", 400);
		}

		await Promise.all([
			this.state.storage.delete(pendingKey),
			this.state.storage.delete(X_ACTIVE_STATE_STORAGE_KEY),
		]);

		if (oauthError) {
			return callbackResponse("X authorization was not completed.", 400);
		}
		if (!code || code.length > 4096) {
			return callbackResponse("Missing or invalid X OAuth authorization code.", 400);
		}

		try {
			const tokens = await this.exchangeAuthorizationCode(code, pending);
			await this.state.storage.put(X_TOKEN_STORAGE_KEY, tokens);
			return callbackResponse("X authorization complete. You can close this window.");
		} catch (error) {
			console.error("X OAuth callback failed", {
				error: error instanceof Error ? error.message : String(error),
			});
			return callbackResponse("X authorization failed while exchanging the code.", 502);
		}
	}

	private async refreshTokens(tokens: XOAuthTokenRecord) {
		if (!this.refreshInFlight) {
			this.refreshInFlight = this.exchangeRefreshToken(tokens).finally(() => {
				this.refreshInFlight = undefined;
			});
		}

		return this.refreshInFlight;
	}

	private async exchangeAuthorizationCode(
		code: string,
		pending: XPendingAuthorization,
	) {
		const response = await this.requestTokens(
			new URLSearchParams({
				code,
				code_verifier: pending.codeVerifier,
				grant_type: "authorization_code",
				redirect_uri: pending.redirectUri,
			}),
		);

		return parseTokenResponse(response, undefined, pending.scopes);
	}

	private async exchangeRefreshToken(tokens: XOAuthTokenRecord) {
		const response = await this.requestTokens(
			new URLSearchParams({
				grant_type: "refresh_token",
				refresh_token: tokens.refreshToken,
			}),
		);
		const refreshed = parseTokenResponse(response, tokens.refreshToken, tokens.scopes);
		await this.state.storage.put(X_TOKEN_STORAGE_KEY, refreshed);
		return refreshed;
	}

	private async requestTokens(body: URLSearchParams) {
		this.requireClientCredentials();
		const credentials = btoa(`${this.env.X_CLIENT_ID}:${this.env.X_CLIENT_SECRET}`);
		const response = await fetch(X_TOKEN_URL, {
			method: "POST",
			headers: {
				Accept: "application/json",
				Authorization: `Basic ${credentials}`,
				"Content-Type": "application/x-www-form-urlencoded",
			},
			body,
			redirect: "manual",
		});
		const payload = (await readJsonResponse(response)) as XTokenResponse;
		if (!response.ok) {
			throw new Error(`X OAuth token endpoint returned HTTP ${response.status}.`);
		}

		return payload;
	}

	private readTokens() {
		return this.state.storage.get<XOAuthTokenRecord>(X_TOKEN_STORAGE_KEY);
	}

	private requireClientCredentials() {
		if (!this.env.X_CLIENT_ID || !this.env.X_CLIENT_SECRET) {
			throw new Error("X_CLIENT_ID and X_CLIENT_SECRET are not configured.");
		}
	}
}

function parseTokenResponse(
	payload: XTokenResponse,
	previousRefreshToken: string | undefined,
	requestedScopes: string[],
): XOAuthTokenRecord {
	if (typeof payload.access_token !== "string" || typeof payload.expires_in !== "number") {
		throw new Error("X OAuth token endpoint returned an invalid token response.");
	}

	const refreshToken =
		typeof payload.refresh_token === "string" ? payload.refresh_token : previousRefreshToken;
	if (!refreshToken) {
		throw new Error("X OAuth did not return a refresh token. Verify offline.access is enabled.");
	}

	return {
		accessToken: payload.access_token,
		expiresAt: Date.now() + payload.expires_in * 1000,
		refreshToken,
		scopes:
			typeof payload.scope === "string"
				? payload.scope.split(" ").filter(Boolean).sort()
				: requestedScopes,
	};
}

async function createCodeChallenge(codeVerifier: string) {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier));
	return bytesToBase64Url(new Uint8Array(digest));
}

function randomBase64Url(byteLength: number) {
	return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(byteLength)));
}

function bytesToBase64Url(bytes: Uint8Array) {
	let binary = "";
	for (const byte of bytes) {
		binary += String.fromCharCode(byte);
	}
	return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

async function readJsonResponse(response: Response) {
	try {
		return (await response.json()) as unknown;
	} catch {
		throw new Error(`X OAuth token endpoint returned a non-JSON response.`);
	}
}

function callbackResponse(body: string, status = 200) {
	return new Response(body, {
		status,
		headers: {
			"Cache-Control": "no-store",
			"Content-Type": "text/plain; charset=utf-8",
			"Referrer-Policy": "no-referrer",
			"X-Content-Type-Options": "nosniff",
		},
	});
}
