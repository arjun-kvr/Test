"""Entrypoint for the insights-reader MCP server."""

import os

from src.security.mcp_auth import build_auth_middleware

from insights_reader_mcp import mcp

# AgentOS platform authentication: every tool call must present a valid
# platform session (`login-token` header -> Redis session -> RS256 JWT ->
# role gate: Super Admin / Admin / Pro code developer). Installed HERE, in the
# deterministic entrypoint, so it applies no matter what the generated server
# module contains — and there is no configuration that removes it. A server
# missing its JWT public key or Redis credentials starts and denies every
# call (fail closed) rather than serving tools anonymously.
mcp.add_middleware(build_auth_middleware("insights-reader"))

if __name__ == "__main__":
    mcp.run(
        transport="http",
        host=os.getenv("MCP_HOST", "0.0.0.0"),
        port=int(os.getenv("MCP_PORT", "8000")),
    )
