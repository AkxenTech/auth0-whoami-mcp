import { createHash } from "node:crypto";
import { createRemoteJWKSet, jwtVerify } from "jose";

export class AuthenticationError extends Error {
  constructor(message) {
    super(message);
    this.name = "AuthenticationError";
  }
}

const jwksByIssuer = new Map();

function headerValue(headers, name) {
  const value = headers?.[name] ?? headers?.[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}

export function bearerToken(headers) {
  const authorization = headerValue(headers, "authorization");
  if (typeof authorization !== "string") {
    throw new AuthenticationError("Missing bearer token.");
  }

  const match = /^Bearer\s+([^\s]+)$/i.exec(authorization.trim());
  if (!match) {
    throw new AuthenticationError("Malformed bearer token.");
  }

  return match[1];
}

export function tokenDiagnostics(token) {
  const segments = typeof token === "string" ? token.split(".") : [];
  return {
    fingerprintPrefix: createHash("sha256").update(token).digest("hex").slice(0, 12),
    length: token.length,
    segmentCount: segments.length,
    isCompactJwt: segments.length === 3 && segments.every(Boolean)
  };
}

function jwksFor(issuer) {
  let jwks = jwksByIssuer.get(issuer);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(".well-known/jwks.json", issuer));
    jwksByIssuer.set(issuer, jwks);
  }
  return jwks;
}

function stringClaim(payload, claim) {
  return typeof payload[claim] === "string" ? payload[claim] : null;
}

function stringArrayClaim(payload, claim) {
  if (Array.isArray(payload[claim])) {
    return payload[claim].filter((value) => typeof value === "string");
  }
  return [];
}

export function authenticatedIdentity(payload) {
  return {
    subject: stringClaim(payload, "sub"),
    name: stringClaim(payload, "name"),
    email: stringClaim(payload, "email"),
    email_verified:
      typeof payload.email_verified === "boolean" ? payload.email_verified : null,
    client_id: stringClaim(payload, "azp") ?? stringClaim(payload, "client_id"),
    scopes:
      typeof payload.scope === "string"
        ? payload.scope.split(/\s+/).filter(Boolean)
        : [],
    permissions: stringArrayClaim(payload, "permissions")
  };
}

export async function verifyAuth0Request(req, config) {
  let token;
  try {
    token = bearerToken(req?.headers);
  } catch (error) {
    if (error instanceof AuthenticationError) {
      throw error;
    }
    throw new AuthenticationError("Unable to read bearer token.");
  }

  try {
    const diagnostics = tokenDiagnostics(token);
    if (!diagnostics.isCompactJwt) {
      throw new AuthenticationError("Access token is not a compact JWT.");
    }

    const { payload } = await jwtVerify(token, jwksFor(config.issuer), {
      issuer: config.issuer,
      audience: config.mcpUrl
    });

    if (typeof payload.sub !== "string" || !payload.sub) {
      throw new AuthenticationError("Access token has no subject.");
    }

    return authenticatedIdentity(payload);
  } catch (error) {
    // The diagnostic intentionally excludes the token, its header, and any secrets.
    console.warn("Auth0 access-token verification failed", tokenDiagnostics(token));
    if (error instanceof AuthenticationError) {
      throw error;
    }
    throw new AuthenticationError("Access token verification failed.");
  }
}
