# Auth0 Who Am I MCP

A minimal, remote MCP server for an Auth0 Custom Extension. Its single tool,
`who_am_i`, returns the safe identity claims from the Auth0 access token that
authenticated the current MCP request.

The server never returns or logs an access token, authorization header, client
secret, or extension secret.

## What the tool returns

`who_am_i` has no inputs and returns a JSON object like:

```json
{
  "subject": "auth0|user-123",
  "name": "Ada Lovelace",
  "email": "ada@example.com",
  "email_verified": true,
  "client_id": "client-123",
  "scopes": ["use:mcp"],
  "permissions": []
}
```

`subject` is the reliable identifier. `name`, `email`, and `email_verified`
are `null` unless those standard claims are included in the access token.

## Build

Use Node 22 or newer. The Custom Extension runtime is explicitly Node 22.

```sh
npm install
npm run build
```

Keep both `index.js` and `build/bundle.js` in the repository: the legacy
Custom Extension importer fetches generated loader artifacts directly.

## Import and configure the Custom Extension

Import or update the extension using `webtask.json`. It declares the required
top-level `"runtime": "node22"`; if you change the manifest, increment its
version and perform a full extension update/reinstall so the dashboard refreshes
the settings schema.

Set these extension settings:

| Setting | Value |
| --- | --- |
| `AUTH0_TENANT_ORIGIN` | Your canonical tenant issuer, for example `https://tenant.us.auth0.com`. |
| `MCP_PUBLIC_URL` | The exact deployed HTTPS endpoint ending in `/mcp`, for example `https://tenant-region.webtask.run/auth0-whoami-mcp/mcp`. |
| `MCP_RESOURCE_METADATA_URL` | Optional. A reachable protected-resource metadata URL; omit it to use the extension-scoped default. |

The server validates a token with all of these constraints:

- Auth0 signature from `AUTH0_TENANT_ORIGIN/.well-known/jwks.json`
- `iss` equal to `AUTH0_TENANT_ORIGIN/`
- `aud` equal to the exact `MCP_PUBLIC_URL`
- JWT expiration and not-before timestamps

For this deliberately simple extension, create the corresponding Auth0 API in
the Dashboard before connecting a client. Its identifier/audience must be
exactly `MCP_PUBLIC_URL`, and it should use RS256 signing. Authorize the client
and user to request that audience. This project does not create a privileged
Management API client or expose a public provisioning route.

## OAuth protected-resource discovery

The extension serves this fallback metadata endpoint:

```text
https://tenant-region.webtask.run/auth0-whoami-mcp/.well-known/oauth-protected-resource/mcp
```

Unauthenticated MCP requests return `401` with a `WWW-Authenticate: Bearer`
challenge that points to it. Some clients first request host-root metadata such
as:

```text
https://tenant-region.webtask.run/.well-known/oauth-protected-resource/auth0-whoami-mcp/mcp
```

Namespaced Custom Extensions cannot normally serve that host-root route. For
those clients, import [`auth0-ext-wellknown`](https://github.com/mustafadeel/auth0-ext-wellknown)
as a separate Custom Extension in the same tenant, keeping its `name` as
`.well-known` and `useHashName` as `false`. Configure its `MCP_RESOURCE_URL`
with the exact `MCP_PUBLIC_URL` above and its `AUTH0_TENANT_ORIGIN` with the
same tenant origin. Configure MCP clients with the actual `/mcp` URL, never
the companion extension URL.

## Validate after deployment

1. `GET /health` returns `200` and a Node `v22...` runtime value.
2. Fetch the protected-resource metadata and confirm its `resource` is exactly
   `MCP_PUBLIC_URL` and its authorization server is the Auth0 issuer.
3. Send an unauthenticated `POST /mcp` and confirm `401` plus a
   `WWW-Authenticate` challenge.
4. Add the complete HTTPS `/mcp` URL to an OAuth-capable MCP client such as
   Codex, Claude, or MCP Inspector. Let it complete OAuth; do not combine the
   OAuth flow with a manually pasted `Authorization` header.
5. Run `initialize`, then invoke `who_am_i`.

## Local verification

```sh
npm test
```

The tests cover configuration, OAuth discovery/challenge behavior, Auth0 JWT
signature/issuer/audience verification, and a Streamable HTTP MCP tool call.
