"""Environment-backed settings for the insights-reader MCP server.

Server-process configuration only (bind address, port). The datasource
connection — host, port, database, user AND credentials — is NEVER read from
the environment: it arrives as tool parameters on every call, injected by the
platform from the configured datasource, so one deployed server serves many
datasources without holding anyone's connection or secrets.
"""

from dataclasses import dataclass


class ConfigError(RuntimeError):
    """A required setting is missing or malformed."""


@dataclass(frozen=True)
class Settings:
    """Immutable snapshot of the process environment."""

    host: str
    port: int
    # No platform settings declared by the plan.

    @classmethod
    def from_env(cls) -> "Settings":
        import os

        def _int(name: str, default: str) -> int:
            raw = os.getenv(name, default)
            try:
                return int(raw)
            except (TypeError, ValueError) as exc:
                raise ConfigError(
                    f"{name} must be an integer, got {raw!r}"
                ) from exc

        return cls(
            host=os.getenv("MCP_HOST", "0.0.0.0"),
            port=_int("MCP_PORT", "8000"),

        )

    def require(self) -> None:
        """No required environment variables for this server."""
        return None


settings = Settings.from_env()
