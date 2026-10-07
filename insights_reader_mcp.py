from __future__ import annotations

from typing import Any, Optional, Sequence

from fastmcp import FastMCP
from pydantic import Field, SecretStr

from src.service import PostgresInsightsService

mcp = FastMCP("insights-reader")
_service = PostgresInsightsService()


def _error(exc: Exception) -> dict[str, Any]:
    return {"status": "failed", "message": str(exc)}


@mcp.tool(
    name="test_connection",
    title="Test Connection",
    description=(
        "Verify that the provided PostgreSQL credentials are valid and the database is reachable "
        "by performing a simple SELECT 1."
    ),
)
async def test_connection(
    host: str = Field(..., description="PostgreSQL host."),
    port: Optional[int] = Field(
        None, description="PostgreSQL port (defaults to 5432 if omitted or null)."
    ),
    database: str = Field(..., description="PostgreSQL database name."),
    username: str = Field(..., description="Database user."),
    password: SecretStr = Field(
        ...,
        description="Database password.",
        json_schema_extra={"format": "password", "ui_type": "password"},
    ),
    connect_timeout_seconds: int = Field(
        10, description="Connection timeout in seconds."
    ),
) -> dict[str, Any]:
    """
    Test a PostgreSQL connection using the provided parameters.

    Args:
        host: PostgreSQL host.
        port: PostgreSQL port (defaults to 5432 if omitted or null).
        database: PostgreSQL database name.
        username: Database user.
        password: Database password (secret).
        connect_timeout_seconds: Connection timeout in seconds.

    Returns:
        On success: {"status":"success","reachable":true}
        On failure: {"status":"failed","message":"..."}
    """
    try:
        result = await _service.test_connection(
            host=host,
            port=port,
            database=database,
            username=username,
            password=password.get_secret_value(),
            connect_timeout_seconds=connect_timeout_seconds,
        )
        return {"status": "success", **result}
    except Exception as exc:
        return _error(exc)


@mcp.tool(
    name="list_schemas",
    title="List Schemas",
    description=(
        "List non-system PostgreSQL schemas visible to the caller "
        "(optionally restricted by schema_filter)."
    ),
)
async def list_schemas(
    host: str = Field(..., description="PostgreSQL host."),
    port: Optional[int] = Field(
        None, description="PostgreSQL port (defaults to 5432 if omitted or null)."
    ),
    database: str = Field(..., description="PostgreSQL database name."),
    username: str = Field(..., description="Database user."),
    password: SecretStr = Field(
        ...,
        description="Database password.",
        json_schema_extra={"format": "password", "ui_type": "password"},
    ),
    schema_filter: Optional[Sequence[str]] = Field(
        None,
        description="Optional allow-list of schemas (empty or omitted = all non-system schemas).",
    ),
) -> dict[str, Any]:
    """
    List visible non-system schemas.

    Args:
        host: PostgreSQL host.
        port: PostgreSQL port (defaults to 5432 if omitted or null).
        database: PostgreSQL database name.
        username: Database user.
        password: Database password (secret).
        schema_filter: Optional allow-list of schema names. If omitted/empty, all non-system schemas.

    Returns:
        On success: {"status":"success","schemas":[{"schema":"..."},...], ...}
        On failure: {"status":"failed","message":"..."}
    """
    try:
        result = await _service.list_schemas(
            host=host,
            port=port,
            database=database,
            username=username,
            password=password.get_secret_value(),
            schema_filter=schema_filter,
        )
        return {"status": "success", **result}
    except Exception as exc:
        return _error(exc)


@mcp.tool(
    name="list_tables",
    title="List Tables / Views",
    description=(
        "List relations in a schema (tables and/or views). Intended for discovering available "
        "insights views so agents do not guess names."
    ),
)
async def list_tables(
    host: str = Field(..., description="PostgreSQL host."),
    port: Optional[int] = Field(
        None, description="PostgreSQL port (defaults to 5432 if omitted or null)."
    ),
    database: str = Field(..., description="PostgreSQL database name."),
    username: str = Field(..., description="Database user."),
    password: SecretStr = Field(
        ...,
        description="Database password.",
        json_schema_extra={"format": "password", "ui_type": "password"},
    ),
    schema_filter: Optional[Sequence[str]] = Field(
        None,
        description="Optional allow-list of schemas (empty or omitted = all non-system schemas).",
    ),
    schema: str = Field(
        "insights", description="Schema to list relations from (default: insights)."
    ),
    include_views: bool = Field(
        True, description="Include views and materialized views."
    ),
    include_tables: bool = Field(False, description="Include base tables."),
) -> dict[str, Any]:
    """
    List relations (tables/views/materialized views) in the given schema.

    Args:
        host: PostgreSQL host.
        port: PostgreSQL port (defaults to 5432 if omitted or null).
        database: PostgreSQL database name.
        username: Database user.
        password: Database password (secret).
        schema_filter: Optional allow-list of schemas.
        schema: Schema to list relations from (default: insights).
        include_views: Include views and materialized views.
        include_tables: Include base tables.

    Returns:
        On success: {"status":"success","relations":[{"schema":"...","name":"...","type":"view|materialized_view|table"},...], ...}
        On failure: {"status":"failed","message":"..."}
    """
    try:
        result = await _service.list_tables(
            host=host,
            port=port,
            database=database,
            username=username,
            password=password.get_secret_value(),
            schema_filter=schema_filter,
            schema=schema,
            include_views=include_views,
            include_tables=include_tables,
        )
        return {"status": "success", **result}
    except Exception as exc:
        return _error(exc)


@mcp.tool(
    name="describe_table",
    title="Describe Table/View",
    description=(
        "Return column names, data types, nullability, and ordinal positions for one table or view."
    ),
)
async def describe_table(
    host: str = Field(..., description="PostgreSQL host."),
    port: Optional[int] = Field(
        None, description="PostgreSQL port (defaults to 5432 if omitted or null)."
    ),
    database: str = Field(..., description="PostgreSQL database name."),
    username: str = Field(..., description="Database user."),
    password: SecretStr = Field(
        ...,
        description="Database password.",
        json_schema_extra={"format": "password", "ui_type": "password"},
    ),
    schema_filter: Optional[Sequence[str]] = Field(
        None,
        description="Optional allow-list of schemas (empty or omitted = all non-system schemas).",
    ),
    schema: str = Field(
        "insights", description="Schema containing the table/view (default: insights)."
    ),
    table_name: str = Field(..., description="Table or view name to describe."),
) -> dict[str, Any]:
    """
    Describe a table or view by returning its columns.

    Args:
        host: PostgreSQL host.
        port: PostgreSQL port (defaults to 5432 if omitted or null).
        database: PostgreSQL database name.
        username: Database user.
        password: Database password (secret).
        schema_filter: Optional allow-list of schemas.
        schema: Schema containing the table/view (default: insights).
        table_name: Table or view name to describe.

    Returns:
        On success: {"status":"success","schema":"...","table":"...","columns":[...]}
        On failure: {"status":"failed","message":"..."}
    """
    try:
        result = await _service.describe_table(
            host=host,
            port=port,
            database=database,
            username=username,
            password=password.get_secret_value(),
            schema_filter=schema_filter,
            schema=schema,
            table_name=table_name,
        )
        return {"status": "success", **result}
    except Exception as exc:
        return _error(exc)


@mcp.tool(
    name="execute_query",
    title="Execute Read-only Query",
    description=(
        "Run a read-only SELECT/WITH query (intended for insights schema reporting) and return "
        "rows capped by max_rows."
    ),
)
async def execute_query(
    host: str = Field(..., description="PostgreSQL host."),
    port: Optional[int] = Field(
        None, description="PostgreSQL port (defaults to 5432 if omitted or null)."
    ),
    database: str = Field(..., description="PostgreSQL database name."),
    username: str = Field(..., description="Database user."),
    password: SecretStr = Field(
        ...,
        description="Database password.",
        json_schema_extra={"format": "password", "ui_type": "password"},
    ),
    schema_filter: Optional[Sequence[str]] = Field(
        None,
        description="Optional allow-list of schemas (empty or omitted = all non-system schemas).",
    ),
    query: str = Field(
        ...,
        description="SQL query text. Must be a single read-only statement starting with SELECT or WITH.",
    ),
    query_params: Optional[Sequence[Any]] = Field(
        None,
        description="Optional positional parameters for psycopg2 (%s placeholders).",
    ),
    max_rows: int = Field(None, description="Maximum number of rows to return."),  # type: ignore[assignment]
    default_schema: str = Field(
        "insights",
        description="Schema to set as the first entry in search_path for the query (default: insights).",
    ),
    enforce_default_schema_only: bool = Field(
        True,
        description=(
            "If true, reject explicit schema-qualified references to schemas other than "
            "default_schema (best-effort validation)."
        ),
    ),
    statement_timeout_seconds: int = Field(
        30,
        description="Server-side statement timeout (seconds) applied via SET LOCAL statement_timeout.",
    ),
) -> dict[str, Any]:
    """
    Execute a single read-only query and return tabular results.

    Args:
        host: PostgreSQL host.
        port: PostgreSQL port (defaults to 5432 if omitted or null).
        database: PostgreSQL database name.
        username: Database user.
        password: Database password (secret).
        schema_filter: Optional allow-list of schemas.
        query: SQL query text; must be a single SELECT/WITH statement.
        query_params: Optional positional parameters matching %s placeholders in query.
        max_rows: Maximum number of rows to return (server enforces internal hard cap).
        default_schema: Schema to prioritize in search_path.
        enforce_default_schema_only: Best-effort restriction on schema-qualified references.
        statement_timeout_seconds: Statement timeout applied via SET LOCAL.

    Returns:
        On success: {"status":"success","columns":[...],"rows":[...],"row_count":N,"truncated":true|false, ...}
        On failure: {"status":"failed","message":"..."}
    """
    try:
        # Keep adapter logic minimal: only apply the documented default when omitted/null.
        effective_max_rows = 200 if max_rows is None else max_rows

        result = await _service.execute_query(
            host=host,
            port=port,
            database=database,
            username=username,
            password=password.get_secret_value(),
            schema_filter=schema_filter,
            query=query,
            query_params=query_params,
            max_rows=effective_max_rows,
            default_schema=default_schema,
            enforce_default_schema_only=enforce_default_schema_only,
            statement_timeout_seconds=statement_timeout_seconds,
        )
        return {"status": "success", **result}
    except Exception as exc:
        return _error(exc)