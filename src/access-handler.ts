import * as oidc from "oauth4webapi";
import {
	AuthorizationError,
	authorizationErrorRedirect,
	CimdFetchError,
	type AuthRequest,
	type OAuthHelpers,
} from "@cloudflare/workers-oauth-provider";
import { renderConsentPage } from "./consent-page";

type EnvWithOauth = Env & { OAUTH_PROVIDER: OAuthHelpers };

export async function handleAccessRequest(request: Request, env: Env) {
	try {
		// OAuthProvider injects its helpers before dispatching to the default handler.
		return await handleAccessRoute(request, env as EnvWithOauth);
	} catch (error) {
		if (error instanceof AuthorizationError) {
			if (error.redirectTo) {
				return Response.redirect(error.redirectTo, 302);
			}
			return new Response(error.description, { status: 400 });
		}
		if (error instanceof CimdFetchError) {
			return new Response("This app could not be verified. Please try again.", { status: 400 });
		}
		throw error;
	}
}

async function handleAccessRoute(request: Request, env: EnvWithOauth) {
	const { pathname, searchParams } = new URL(request.url);
	const oauth = env.OAUTH_PROVIDER;
	const remember = { secret: env.COOKIE_ENCRYPTION_KEY };

	if (request.method === "GET" && pathname === "/authorize") {
		const authRequest = await oauth.parseAuthRequest(request);
		if (await oauth.isConsentRemembered(request, authRequest, remember)) {
			return redirectToAccess(request, env, authRequest);
		}
		const details = await oauth.describeConsent(authRequest);
		const consent = await oauth.beginConsent(authRequest);
		consent.headers.set("Content-Type", "text/html; charset=utf-8");
		return new Response(renderConsentPage(details, consent.handle), { headers: consent.headers });
	}

	if (request.method === "POST" && pathname === "/authorize") {
		const form = await request.formData();
		const handle = form.get("handle");
		if (typeof handle !== "string") {
			return new Response("Missing consent handle", { status: 400 });
		}
		if (form.get("decision") === "deny") {
			const denied = await oauth.denyConsent(request, handle);
			return new Response(null, { status: 302, headers: denied.headers });
		}
		if (form.get("decision") !== "approve") {
			return new Response("Invalid consent decision", { status: 400 });
		}
		const approved = await oauth.approveConsent(request, handle, { remember });
		return redirectToAccess(request, env, approved.request, approved.headers);
	}

	if (request.method === "GET" && pathname === "/callback") {
		const resumed = await oauth.finishUpstream<{ codeVerifier: string }>(request);
		if (searchParams.has("error")) {
			resumed.headers.set("Location", authorizationErrorRedirect(resumed.request, "access_denied"));
			return new Response(null, { status: 302, headers: resumed.headers });
		}
		const code = searchParams.get("code");
		if (!code) {
			return new Response("Missing authorization code", { status: 400, headers: resumed.headers });
		}

		let identity;
		try {
			identity = await authenticateWithAccess(request, env, resumed.data.codeVerifier);
		} catch {
			return new Response("Access identity could not be verified.", { status: 400, headers: resumed.headers });
		}
		const { tokens, user } = identity;
		const { redirectTo } = await oauth.completeAuthorization({
			metadata: { label: user.name },
			props: {
				accessToken: tokens.access_token,
				email: user.email,
				login: user.sub,
				name: user.name,
			},
			request: resumed.request,
			scope: resumed.request.scope,
			userId: user.sub,
		});
		resumed.headers.set("Location", redirectTo);
		return new Response(null, { status: 302, headers: resumed.headers });
	}
	return new Response("Not Found", { status: 404 });
}

async function redirectToAccess(
	request: Request,
	env: EnvWithOauth,
	authRequest: AuthRequest,
	headers?: Headers,
) {
	const codeVerifier = oidc.generateRandomCodeVerifier();
	const codeChallenge = await oidc.calculatePKCECodeChallenge(codeVerifier);
	const upstream = await env.OAUTH_PROVIDER.beginUpstream(authRequest, {
		data: { codeVerifier },
		headers,
	});
	const url = new URL(env.ACCESS_AUTHORIZATION_URL);
	const params = {
		client_id: env.ACCESS_CLIENT_ID,
		redirect_uri: new URL("/callback", request.url).href,
		response_type: "code",
		scope: "openid email profile",
		state: upstream.state,
		code_challenge: codeChallenge,
		code_challenge_method: "S256",
	};
	for (const [key, value] of Object.entries(params)) {
		url.searchParams.set(key, value);
	}
	upstream.headers.set("Location", url.href);
	return new Response(null, { status: 302, headers: upstream.headers });
}

async function authenticateWithAccess(request: Request, env: Env, codeVerifier: string) {
	// Access for SaaS places /jwks directly under its OIDC issuer URL.
	const server: oidc.AuthorizationServer = {
		issuer: new URL(".", env.ACCESS_JWKS_URL).href.replace(/\/$/, ""),
		token_endpoint: env.ACCESS_TOKEN_URL,
		jwks_uri: env.ACCESS_JWKS_URL,
	};
	const client: oidc.Client = {
		client_id: env.ACCESS_CLIENT_ID,
		id_token_signed_response_alg: "RS256",
		[oidc.clockTolerance]: 0,
	};
	// finishUpstream already verified and consumed the browser-bound state transaction.
	const parameters = oidc.validateAuthResponse(server, client, new URL(request.url), oidc.skipStateCheck);
	const signal = AbortSignal.timeout(20_000);
	const response = await oidc.authorizationCodeGrantRequest(
		server, client, oidc.ClientSecretPost(env.ACCESS_CLIENT_SECRET), parameters,
		new URL("/callback", request.url).href, codeVerifier, { signal },
	);
	const tokens = await oidc.processAuthorizationCodeResponse(server, client, response, {
		requireIdToken: true,
	});
	await oidc.validateApplicationLevelSignature(server, response, { signal });
	const payload = oidc.getValidatedIdTokenClaims(tokens)!;
	// Concierge accepts only its own audience, even when OIDC would allow additional audiences.
	if (
		typeof payload.sub !== "string" || !payload.sub ||
		!Number.isFinite(payload.exp) || !Number.isFinite(payload.iat) ||
		(Array.isArray(payload.aud) && payload.aud.some((audience) => audience !== env.ACCESS_CLIENT_ID)) ||
		(payload.azp !== undefined && payload.azp !== env.ACCESS_CLIENT_ID)
	) {
		throw new Error("Invalid Access identity claims.");
	}
	return {
		tokens,
		user: {
			sub: payload.sub,
			name: typeof payload.name === "string" ? payload.name : payload.sub,
			email: typeof payload.email === "string" ? payload.email : undefined,
		},
	};
}
