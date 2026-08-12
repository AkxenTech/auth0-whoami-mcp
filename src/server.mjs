import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

export function createIdentityServer(identity) {
  const server = new McpServer({
    name: "auth0-whoami-mcp",
    version: "1.0.0"
  });

  server.registerTool(
    "who_am_i",
    {
      description:
        "Return the safe identity claims from the Auth0 access token authenticated for this MCP request.",
      inputSchema: {}
    },
    async () => ({
      content: [
        {
          type: "text",
          text: JSON.stringify(identity)
        }
      ]
    })
  );

  return server;
}

export async function handleMcpRequest(req, res, identity) {
  const server = createIdentityServer(identity);
  const transport = new StreamableHTTPServerTransport({
    // The Webtask platform has no affinity guarantee, so every request is stateless.
    sessionIdGenerator: undefined
  });

  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } finally {
    await transport.close();
  }
}
