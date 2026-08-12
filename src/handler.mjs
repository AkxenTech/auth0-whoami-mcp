import {
  ConfigurationError,
  deploymentConfig,
  isHealthPath,
  isMcpPath,
  isProtectedResourceMetadataPath,
  requestPath
} from "./config.mjs";
import { AuthenticationError, verifyAuth0Request } from "./auth.mjs";
import { handleMcpRequest } from "./server.mjs";

function sendJson(res, status, body, headers = {}) {
  res.statusCode = status;
  res.setHeader("content-type", "application/json; charset=utf-8");
  for (const [name, value] of Object.entries(headers)) {
    res.setHeader(name, value);
  }
  res.end(JSON.stringify(body));
}

function sendEmpty(res, status, headers = {}) {
  res.statusCode = status;
  for (const [name, value] of Object.entries(headers)) {
    res.setHeader(name, value);
  }
  res.end();
}

function resourceChallenge(config) {
  return `Bearer resource_metadata="${config.metadataUrl}"`;
}

function alreadyResponded(res) {
  return Boolean(res.headersSent || res.writableEnded || res.finished);
}

export function createExtensionHandler({
  verifyRequest = verifyAuth0Request,
  handleMcp = handleMcpRequest
} = {}) {
  return async function extensionHandler(context, req, res) {
    const pathname = requestPath(req);
    const method = (req?.method ?? "GET").toUpperCase();

    if (isHealthPath(pathname)) {
      sendJson(res, 200, {
        status: "ok",
        runtime: process.version
      });
      return;
    }

    let config;
    try {
      config = deploymentConfig(context);
    } catch (error) {
      if (error instanceof ConfigurationError) {
        console.error("MCP extension configuration is invalid", { code: "configuration_error" });
        sendJson(res, 500, { error: "configuration_error" });
        return;
      }
      throw error;
    }

    if (isProtectedResourceMetadataPath(pathname)) {
      if (method !== "GET") {
        sendJson(res, 405, { error: "method_not_allowed" }, { allow: "GET" });
        return;
      }

      sendJson(res, 200, {
        resource: config.mcpUrl,
        authorization_servers: [config.issuer]
      });
      return;
    }

    if (!isMcpPath(pathname)) {
      sendJson(res, 404, { error: "not_found" });
      return;
    }

    if (method === "OPTIONS") {
      sendEmpty(res, 204, { allow: "GET, POST, OPTIONS" });
      return;
    }

    try {
      const identity = await verifyRequest(req, config);
      await handleMcp(req, res, identity);
    } catch (error) {
      if (alreadyResponded(res)) {
        return;
      }

      if (error instanceof AuthenticationError) {
        sendJson(
          res,
          401,
          { error: "unauthorized" },
          { "www-authenticate": resourceChallenge(config) }
        );
        return;
      }

      console.error("MCP request failed", { code: "mcp_request_failed" });
      sendJson(res, 500, { error: "internal_server_error" });
    }
  };
}

export const handler = createExtensionHandler();
