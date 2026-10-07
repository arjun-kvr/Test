from __future__ import annotations

from typing import Any, Dict
from unittest.mock import AsyncMock

import pytest
from pydantic import SecretStr

import insights_reader_mcp


@pytest.mark.asyncio
async def test_test_connection_success_envelope(monkeypatch: pytest.MonkeyPatch) -> None:
    mocked = AsyncMock(return_value={"reachable": True})
    monkeypatch.setattr(insights_reader_mcp._service, "test_connection", mocked)

    result = await insights_reader_mcp.test_connection(
        host="db.example.internal",
        port=None,
        database="platform",
        username="readonly_user",
        password=SecretStr("s3cr3t"),
        connect_timeout_seconds=5,
    )

    assert result == {"status": "success", "reachable": True}

    mocked.assert_awaited_once()
    kwargs: Dict[str, Any] = mocked.call_args.kwargs
    assert kwargs["host"] == "db.example.internal"
    assert kwargs["port"] is None
    assert kwargs["database"] == "platform"
    assert kwargs["username"] == "readonly_user"
    assert kwargs["password"] == "s3cr3t"
    assert kwargs["connect_timeout_seconds"] == 5


@pytest.mark.asyncio
async def test_test_connection_failure_envelope(monkeypatch: pytest.MonkeyPatch) -> None:
    mocked = AsyncMock(side_effect=RuntimeError("connection failed"))
    monkeypatch.setattr(insights_reader_mcp._service, "test_connection", mocked)

    result = await insights_reader_mcp.test_connection(
        host="db.example.internal",
        port=5432,
        database="platform",
        username="readonly_user",
        password=SecretStr("bad"),
        connect_timeout_seconds=2,
    )

    assert result == {"status": "failed", "message": "connection failed"}
    mocked.assert_awaited_once()


@pytest.mark.asyncio
async def test_list_schemas_success_envelope(monkeypatch: pytest.MonkeyPatch) -> None:
    mocked = AsyncMock(
        return_value={
            "schemas": [{"schema": "insights"}, {"schema": "public"}],
            "truncated": False,
        }
    )
    monkeypatch.setattr(insights_reader_mcp._service, "list_schemas", mocked)

    result = await insights_reader_mcp.list_schemas(
        host="db.example.internal",
        port=None,
        database="platform",
        username="readonly_user",
        password=SecretStr("pw"),
        schema_filter=None,
    )

    assert result == {
        "status": "success",
        "schemas": [{"schema": "insights"}, {"schema": "public"}],
        "truncated": False,
    }

    mocked.assert_awaited_once()
    kwargs: Dict[str, Any] = mocked.call_args.kwargs
    assert kwargs["host"] == "db.example.internal"
    assert kwargs["port"] is None
    assert kwargs["database"] == "platform"
    assert kwargs["username"] == "readonly_user"
    assert kwargs["password"] == "pw"
    assert kwargs["schema_filter"] is None


@pytest.mark.asyncio
async def test_list_schemas_failure_envelope(monkeypatch: pytest.MonkeyPatch) -> None:
    mocked = AsyncMock(side_effect=ValueError("schema_filter must be an array"))
    monkeypatch.setattr(insights_reader_mcp._service, "list_schemas", mocked)

    result = await insights_reader_mcp.list_schemas(
        host="db.example.internal",
        port=5432,
        database="platform",
        username="readonly_user",
        password=SecretStr("pw"),
        schema_filter=["insights"],
    )

    assert result == {"status": "failed", "message": "schema_filter must be an array"}
    mocked.assert_awaited_once()


@pytest.mark.asyncio
async def test_list_tables_success_envelope(monkeypatch: pytest.MonkeyPatch) -> None:
    mocked = AsyncMock(
        return_value={
            "relations": [
                {"schema": "insights", "name": "usage_daily", "type": "view"},
                {"schema": "insights", "name": "events_mv", "type": "materialized_view"},
            ]
        }
    )
    monkeypatch.setattr(insights_reader_mcp._service, "list_tables", mocked)

    result = await insights_reader_mcp.list_tables(
        host="db.example.internal",
        port=None,
        database="platform",
        username="readonly_user",
        password=SecretStr("pw"),
        schema_filter=None,
        schema="insights",
        include_views=True,
        include_tables=False,
    )

    assert result == {
        "status": "success",
        "relations": [
            {"schema": "insights", "name": "usage_daily", "type": "view"},
            {"schema": "insights", "name": "events_mv", "type": "materialized_view"},
        ],
    }

    mocked.assert_awaited_once()
    kwargs: Dict[str, Any] = mocked.call_args.kwargs
    assert kwargs["host"] == "db.example.internal"
    assert kwargs["port"] is None
    assert kwargs["database"] == "platform"
    assert kwargs["username"] == "readonly_user"
    assert kwargs["password"] == "pw"
    assert kwargs["schema_filter"] is None
    assert kwargs["schema"] == "insights"
    assert kwargs["include_views"] is True
    assert kwargs["include_tables"] is False


@pytest.mark.asyncio
async def test_list_tables_failure_envelope(monkeypatch: pytest.MonkeyPatch) -> None:
    mocked = AsyncMock(side_effect=ValueError("Schema 'secret' is not allowed"))
    monkeypatch.setattr(insights_reader_mcp._service, "list_tables", mocked)

    result = await insights_reader_mcp.list_tables(
        host="db.example.internal",
        port=5432,
        database="platform",
        username="readonly_user",
        password=SecretStr("pw"),
        schema_filter=["insights"],
        schema="secret",
        include_views=True,
        include_tables=False,
    )

    assert result == {"status": "failed", "message": "Schema 'secret' is not allowed"}
    mocked.assert_awaited_once()


@pytest.mark.asyncio
async def test_describe_table_success_envelope(monkeypatch: pytest.MonkeyPatch) -> None:
    mocked = AsyncMock(
        return_value={
            "schema": "insights",
            "table": "usage_daily",
            "columns": [
                {
                    "name": "day",
                    "data_type": "date",
                    "nullable": False,
                    "ordinal_position": 1,
                },
                {
                    "name": "count",
                    "data_type": "bigint",
                    "nullable": True,
                    "ordinal_position": 2,
                },
            ],
        }
    )
    monkeypatch.setattr(insights_reader_mcp._service, "describe_table", mocked)

    result = await insights_reader_mcp.describe_table(
        host="db.example.internal",
        port=None,
        database="platform",
        username="readonly_user",
        password=SecretStr("pw"),
        schema_filter=None,
        schema="insights",
        table_name="usage_daily",
    )

    assert result == {
        "status": "success",
        "schema": "insights",
        "table": "usage_daily",
        "columns": [
            {"name": "day", "data_type": "date", "nullable": False, "ordinal_position": 1},
            {"name": "count", "data_type": "bigint", "nullable": True, "ordinal_position": 2},
        ],
    }

    mocked.assert_awaited_once()
    kwargs: Dict[str, Any] = mocked.call_args.kwargs
    assert kwargs["host"] == "db.example.internal"
    assert kwargs["port"] is None
    assert kwargs["database"] == "platform"
    assert kwargs["username"] == "readonly_user"
    assert kwargs["password"] == "pw"
    assert kwargs["schema_filter"] is None
    assert kwargs["schema"] == "insights"
    assert kwargs["table_name"] == "usage_daily"


@pytest.mark.asyncio
async def test_describe_table_failure_envelope(monkeypatch: pytest.MonkeyPatch) -> None:
    mocked = AsyncMock(side_effect=RuntimeError("relation not found"))
    monkeypatch.setattr(insights_reader_mcp._service, "describe_table", mocked)

    result = await insights_reader_mcp.describe_table(
        host="db.example.internal",
        port=5432,
        database="platform",
        username="readonly_user",
        password=SecretStr("pw"),
        schema_filter=None,
        schema="insights",
        table_name="missing_view",
    )

    assert result == {"status": "failed", "message": "relation not found"}
    mocked.assert_awaited_once()


@pytest.mark.asyncio
async def test_execute_query_success_envelope_and_default_max_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mocked = AsyncMock(
        return_value={
            "columns": ["a"],
            "rows": [{"a": 1}],
            "row_count": 1,
            "truncated": False,
        }
    )
    monkeypatch.setattr(insights_reader_mcp._service, "execute_query", mocked)

    result = await insights_reader_mcp.execute_query(
        host="db.example.internal",
        port=None,
        database="platform",
        username="readonly_user",
        password=SecretStr("s3cr3t"),
        schema_filter=None,
        query="select 1 as a",
        query_params=None,
        max_rows=None,  # adapter should default to 200
        default_schema="insights",
        enforce_default_schema_only=True,
        statement_timeout_seconds=10,
    )

    assert result == {
        "status": "success",
        "columns": ["a"],
        "rows": [{"a": 1}],
        "row_count": 1,
        "truncated": False,
    }

    mocked.assert_awaited_once()
    kwargs: Dict[str, Any] = mocked.call_args.kwargs
    assert kwargs["max_rows"] == 200
    assert kwargs["password"] == "s3cr3t"
    assert kwargs["default_schema"] == "insights"
    assert kwargs["enforce_default_schema_only"] is True
    assert kwargs["statement_timeout_seconds"] == 10


@pytest.mark.asyncio
async def test_execute_query_failure_envelope(monkeypatch: pytest.MonkeyPatch) -> None:
    mocked = AsyncMock(side_effect=RuntimeError("Disallowed keyword detected in query: DROP"))
    monkeypatch.setattr(insights_reader_mcp._service, "execute_query", mocked)

    result = await insights_reader_mcp.execute_query(
        host="db.example.internal",
        port=5432,
        database="platform",
        username="readonly_user",
        password=SecretStr("pw"),
        schema_filter=None,
        query="drop table insights.usage_daily",
        query_params=None,
        max_rows=10,
        default_schema="insights",
        enforce_default_schema_only=True,
        statement_timeout_seconds=5,
    )

    assert result == {
        "status": "failed",
        "message": "Disallowed keyword detected in query: DROP",
    }
    mocked.assert_awaited_once()