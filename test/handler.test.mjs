import assert from "node:assert/strict";
import test from "node:test";

import { AuthenticationError } from "../src/auth.mjs";
import { createExtensionHandler } from "../src/handler.mjs";

class TestResponse {
  constructor() {
    this.headers = {};
    this.statusCode = 200;
    this.headersSent = false;
    this.writableEnded = false;
    this.finished = false;
    this.body = "";
  }

  setHeader(name, value) {
    this.headers[name.toLowerCase()] = value;
  }

  end(body = "") {
    this.body = body;
    this.headersSent = true;
    this.writableEnded = true;
    this.finished = true;
  }
}

const settings = {
  data: {
    AUTH0_TENANT_ORIGIN: "https://example.us.auth0.com",
    MCP_PUBLIC_URL: "https://tenant-region.webtask.run/auth0-whoami-mcp/mcp"
  }
};

function request(url, method = "GET") {
  return { url, method, headers: {} };
}

test("health is available before extension settings are configured", async () => {
  const handler = createExtensionHandler();
  const res = new TestResponse();

  await handler({}, request("/auth0-whoami-mcp/health"), res);

  assert.equal(res.statusCode, 200);
  assert.equal(JSON.parse(res.body).status, "ok");
  assert.match(JSON.parse(res.body).runtime, /^v/);
});

test("publishes protected-resource metadata with the exact MCP audience", async () => {
  const handler = createExtensionHandler();
  const res = new TestResponse();

  await handler(
    settings,
    request("/auth0-whoami-mcp/.well-known/oauth-protected-resource/mcp"),
    res
  );

  assert.equal(res.statusCode, 200);
  assert.deepEqual(JSON.parse(res.body), {
    resource: "https://tenant-region.webtask.run/auth0-whoami-mcp/mcp",
    authorization_servers: ["https://example.us.auth0.com/"]
  });
});

test("returns an OAuth challenge before it lets unauthenticated traffic reach MCP", async () => {
  const handler = createExtensionHandler({
    verifyRequest: async () => {
      throw new AuthenticationError("Rejected for test");
    }
  });
  const res = new TestResponse();

  await handler(settings, request("/auth0-whoami-mcp/mcp", "POST"), res);

  assert.equal(res.statusCode, 401);
  assert.equal(
    res.headers["www-authenticate"],
    'Bearer resource_metadata="https://tenant-region.webtask.run/auth0-whoami-mcp/.well-known/oauth-protected-resource/mcp"'
  );
  assert.deepEqual(JSON.parse(res.body), { error: "unauthorized" });
});

test("passes the verified identity, not the token, into MCP handling", async () => {
  const identity = { subject: "auth0|user-123", email: "ada@example.test" };
  let receivedIdentity;
  const handler = createExtensionHandler({
    verifyRequest: async () => identity,
    handleMcp: async (_req, res, verifiedIdentity) => {
      receivedIdentity = verifiedIdentity;
      res.statusCode = 200;
      res.end(JSON.stringify({ accepted: true }));
    }
  });
  const res = new TestResponse();

  await handler(settings, request("/auth0-whoami-mcp/mcp", "POST"), res);

  assert.deepEqual(receivedIdentity, identity);
  assert.deepEqual(JSON.parse(res.body), { accepted: true });
});
