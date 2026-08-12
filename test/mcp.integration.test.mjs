import assert from "node:assert/strict";
import { once } from "node:events";
import http from "node:http";
import test from "node:test";

import { createExtensionHandler } from "../src/handler.mjs";

const settings = {
  data: {
    AUTH0_TENANT_ORIGIN: "https://example.us.auth0.com",
    MCP_PUBLIC_URL: "https://tenant-region.webtask.run/auth0-whoami-mcp/mcp"
  }
};

async function startServer(handler) {
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) {
      chunks.push(chunk);
    }

    const body = Buffer.concat(chunks).toString("utf8");
    req.body = body ? JSON.parse(body) : undefined;
    await handler(settings, req, res);
  });

  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const { port } = server.address();

  return {
    url: `http://127.0.0.1:${port}/auth0-whoami-mcp/mcp`,
    async close() {
      server.close();
      await once(server, "close");
    }
  };
}

async function postMcp(url, body) {
  return fetch(url, {
    method: "POST",
    headers: {
      accept: "application/json, text/event-stream",
      authorization: "Bearer test.token.value",
      "content-type": "application/json"
    },
    body: JSON.stringify(body)
  });
}

async function jsonRpcResponse(response) {
  const responseText = await response.text();
  if (response.headers.get("content-type")?.includes("text/event-stream")) {
    const messages = [...responseText.matchAll(/^data:\s*(.+)$/gm)];
    assert.ok(messages.length, "SSE response must contain a JSON-RPC data message");
    return JSON.parse(messages.at(-1)[1]);
  }
  return JSON.parse(responseText);
}

test("serves the who_am_i tool over stateless Streamable HTTP", async () => {
  const identity = {
    subject: "auth0|user-123",
    name: "Ada Lovelace",
    email: "ada@example.test",
    email_verified: true,
    client_id: "client-123",
    scopes: ["use:mcp"],
    permissions: []
  };
  const handler = createExtensionHandler({
    verifyRequest: async () => identity
  });
  const server = await startServer(handler);

  try {
    const initialize = await postMcp(server.url, {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "test-client", version: "1.0.0" }
      }
    });

    assert.equal(initialize.status, 200);
    const initialized = await jsonRpcResponse(initialize);
    assert.equal(initialized.result.serverInfo.name, "auth0-whoami-mcp");

    const toolCall = await postMcp(server.url, {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "who_am_i", arguments: {} }
    });

    assert.equal(toolCall.status, 200);
    const result = await jsonRpcResponse(toolCall);
    assert.deepEqual(JSON.parse(result.result.content[0].text), identity);
  } finally {
    await server.close();
  }
});
