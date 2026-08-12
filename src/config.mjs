export class ConfigurationError extends Error {
  constructor(message) {
    super(message);
    this.name = "ConfigurationError";
  }
}

function settingFrom(context, name) {
  const sources = [
    context?.data,
    context?.secrets,
    context?.webtask?.data,
    context?.webtask?.secrets
  ];

  for (const source of sources) {
    const value = source?.[name];
    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }

  return undefined;
}

function requireSetting(context, name) {
  const value = settingFrom(context, name);
  if (!value) {
    throw new ConfigurationError(`Missing required extension setting: ${name}`);
  }
  return value;
}

function parseHttpsUrl(value, name) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new ConfigurationError(`${name} must be an absolute HTTPS URL.`);
  }

  if (url.protocol !== "https:" || url.username || url.password) {
    throw new ConfigurationError(`${name} must be an absolute HTTPS URL.`);
  }

  return url;
}

function tenantOrigin(value) {
  const url = parseHttpsUrl(value, "AUTH0_TENANT_ORIGIN");
  if (url.pathname !== "/" || url.search || url.hash) {
    throw new ConfigurationError(
      "AUTH0_TENANT_ORIGIN must contain only the Auth0 tenant origin."
    );
  }
  return url.origin;
}

function publicMcpUrl(value) {
  const url = parseHttpsUrl(value, "MCP_PUBLIC_URL");
  if (url.search || url.hash || !url.pathname.endsWith("/mcp")) {
    throw new ConfigurationError(
      "MCP_PUBLIC_URL must be the exact public HTTPS URL of the /mcp endpoint."
    );
  }
  return url.href;
}

function metadataUrl(context, mcpUrl) {
  const configured = settingFrom(context, "MCP_RESOURCE_METADATA_URL");
  if (!configured) {
    return new URL("./.well-known/oauth-protected-resource/mcp", mcpUrl).href;
  }

  const url = parseHttpsUrl(configured, "MCP_RESOURCE_METADATA_URL");
  if (url.search || url.hash) {
    throw new ConfigurationError(
      "MCP_RESOURCE_METADATA_URL must not include a query string or fragment."
    );
  }
  return url.href;
}

export function deploymentConfig(context) {
  const origin = tenantOrigin(requireSetting(context, "AUTH0_TENANT_ORIGIN"));
  const mcpUrl = publicMcpUrl(requireSetting(context, "MCP_PUBLIC_URL"));

  return Object.freeze({
    tenantOrigin: origin,
    issuer: `${origin}/`,
    mcpUrl,
    metadataUrl: metadataUrl(context, mcpUrl)
  });
}

export function requestPath(req) {
  const rawPath = req?.originalUrl ?? req?.url ?? req?.path ?? "/";

  try {
    return new URL(rawPath, "https://webtask.invalid").pathname;
  } catch {
    return "/";
  }
}

export function isMcpPath(pathname) {
  return pathname === "/mcp" || pathname.endsWith("/mcp");
}

export function isHealthPath(pathname) {
  return pathname === "/health" || pathname.endsWith("/health");
}

export function isProtectedResourceMetadataPath(pathname) {
  const suffix = "/.well-known/oauth-protected-resource/mcp";
  return pathname === suffix || pathname.endsWith(suffix);
}
