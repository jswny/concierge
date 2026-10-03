import { Buffer } from "node:buffer";
import { createRemoteJWKSet, jwtVerify } from "jose";
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

		const tokens = await exchangeAccessCode(request, env, code, resumed.data.codeVerifier);
		let user;
		try {
			user = await verifyToken(env, tokens.id_token);
		} catch {
			return new Response("Access identity could not be verified.", { status: 400, headers: resumed.headers });
		}
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
	const codeVerifier = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url");
	const codeChallenge = Buffer.from(
		await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier)),
	).toString("base64url");
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

async function exchangeAccessCode(request: Request, env: Env, code: string, codeVerifier: string) {
	const response = await fetch(env.ACCESS_TOKEN_URL, {
		method: "POST",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded",
			Accept: "application/json",
		},
		body: new URLSearchParams({
			client_id: env.ACCESS_CLIENT_ID,
			client_secret: env.ACCESS_CLIENT_SECRET,
			code,
			grant_type: "authorization_code",
			redirect_uri: new URL("/callback", request.url).href,
			code_verifier: codeVerifier,
		}),
	});
	if (!response.ok) {
		throw new Error(`Access token exchange failed with HTTP ${response.status}.`);
	}
	const tokens = (await response.json()) as { access_token?: unknown; id_token?: unknown };
	if (typeof tokens.access_token !== "string" || typeof tokens.id_token !== "string") {
		throw new Error("Access token response is missing required tokens.");
	}
	return { access_token: tokens.access_token, id_token: tokens.id_token };
}

async function verifyToken(env: Env, token: string) {
	const jwksUrl = new URL(env.ACCESS_JWKS_URL);
	// Access for SaaS places /jwks directly under its OIDC issuer URL.
	const issuer = new URL(".", jwksUrl).href.replace(/\/$/, "");
	const { payload } = await jwtVerify(token, createRemoteJWKSet(jwksUrl), {
		algorithms: ["RS256"],
		audience: env.ACCESS_CLIENT_ID,
		issuer,
		requiredClaims: ["exp", "iat", "sub"],
	});
	if (
		typeof payload.sub !== "string" || !payload.sub ||
		!Number.isFinite(payload.exp) || !Number.isFinite(payload.iat) ||
		(Array.isArray(payload.aud) && payload.aud.some((audience) => audience !== env.ACCESS_CLIENT_ID)) ||
		(payload.azp !== undefined && payload.azp !== env.ACCESS_CLIENT_ID)
	) {
		throw new Error("Invalid Access identity claims.");
	}
	return {
		sub: payload.sub,
		name: typeof payload.name === "string" ? payload.name : payload.sub,
		email: typeof payload.email === "string" ? payload.email : undefined,
	};
}
