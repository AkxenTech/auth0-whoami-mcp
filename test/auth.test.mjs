import assert from "node:assert/strict";
import test from "node:test";
import { SignJWT, exportJWK, generateKeyPair } from "jose";

import {
  AuthenticationError,
  authenticatedIdentity,
  bearerToken,
  tokenDiagnostics,
  verifyAuth0Request
} from "../src/auth.mjs";

test("extracts a bearer token without retaining its header", () => {
  assert.equal(
    bearerToken({ authorization: "Bearer header.payload.signature" }),
    "header.payload.signature"
  );
  assert.throws(() => bearerToken({}), AuthenticationError);
  assert.throws(() => bearerToken({ authorization: "Basic abc" }), AuthenticationError);
});

test("returns only safe identity claims for the identity tool", () => {
  assert.deepEqual(
    authenticatedIdentity({
      sub: "auth0|user-123",
      name: "Ada Lovelace",
      email: "ada@example.test",
      email_verified: true,
      azp: "abc123",
      scope: "read:profile use:mcp",
      permissions: ["read:profile", 42],
      secret_claim: "never exposed"
    }),
    {
      subject: "auth0|user-123",
      name: "Ada Lovelace",
      email: "ada@example.test",
      email_verified: true,
      client_id: "abc123",
      scopes: ["read:profile", "use:mcp"],
      permissions: ["read:profile"]
    }
  );
});

test("produces token-safe failure diagnostics", () => {
  assert.deepEqual(tokenDiagnostics("one.two.three"), {
    fingerprintPrefix: "57eba23aff82",
    length: 13,
    segmentCount: 3,
    isCompactJwt: true
  });
});

test("verifies an Auth0 JWT against the tenant JWKS and exact MCP audience", async () => {
  const issuer = "https://verification-example.us.auth0.com/";
  const mcpUrl = "https://tenant-region.webtask.run/auth0-whoami-mcp/mcp";
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const publicJwk = await exportJWK(publicKey);
  publicJwk.kid = "test-key";

  const token = await new SignJWT({
    email: "ada@example.test",
    scope: "use:mcp"
  })
    .setProtectedHeader({ alg: "RS256", kid: "test-key" })
    .setSubject("auth0|user-123")
    .setIssuer(issuer)
    .setAudience(mcpUrl)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(privateKey);

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input) => {
    assert.equal(
      String(input),
      "https://verification-example.us.auth0.com/.well-known/jwks.json"
    );
    return new Response(JSON.stringify({ keys: [publicJwk] }), {
      headers: { "content-type": "application/json" }
    });
  };

  try {
    const identity = await verifyAuth0Request(
      { headers: { authorization: `Bearer ${token}` } },
      { issuer, mcpUrl }
    );

    assert.deepEqual(identity, {
      subject: "auth0|user-123",
      name: null,
      email: "ada@example.test",
      email_verified: null,
      client_id: null,
      scopes: ["use:mcp"],
      permissions: []
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});
