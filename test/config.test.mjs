import assert from "node:assert/strict";
import test from "node:test";

import {
  ConfigurationError,
  deploymentConfig,
  isHealthPath,
  isMcpPath,
  isProtectedResourceMetadataPath
} from "../src/config.mjs";

const context = {
  data: {
    AUTH0_TENANT_ORIGIN: "https://example.us.auth0.com",
    MCP_PUBLIC_URL: "https://tenant-region.webtask.run/auth0-whoami-mcp/mcp"
  }
};

test("creates an exact issuer, MCP audience, and extension-scoped metadata URL", () => {
  assert.deepEqual(deploymentConfig(context), {
    tenantOrigin: "https://example.us.auth0.com",
    issuer: "https://example.us.auth0.com/",
    mcpUrl: "https://tenant-region.webtask.run/auth0-whoami-mcp/mcp",
    metadataUrl:
      "https://tenant-region.webtask.run/auth0-whoami-mcp/.well-known/oauth-protected-resource/mcp"
  });
});

test("rejects a bare tenant hostname and a non-MCP public URL", () => {
  assert.throws(
    () =>
      deploymentConfig({
        data: {
          ...context.data,
          AUTH0_TENANT_ORIGIN: "example.us.auth0.com"
        }
      }),
    ConfigurationError
  );

  assert.throws(
    () =>
      deploymentConfig({
        data: {
          ...context.data,
          MCP_PUBLIC_URL: "https://tenant-region.webtask.run/auth0-whoami-mcp"
        }
      }),
    ConfigurationError
  );
});

test("recognizes extension-scoped routes", () => {
  assert.equal(isHealthPath("/auth0-whoami-mcp/health"), true);
  assert.equal(isMcpPath("/auth0-whoami-mcp/mcp"), true);
  assert.equal(
    isProtectedResourceMetadataPath(
      "/auth0-whoami-mcp/.well-known/oauth-protected-resource/mcp"
    ),
    true
  );
});
