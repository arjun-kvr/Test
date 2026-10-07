"""Security primitives for this MCP server (AgentOS platform authentication)."""

from src.security.mcp_auth import build_auth_middleware

__all__ = ["build_auth_middleware"]
