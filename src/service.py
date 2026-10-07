from __future__ import annotations

import asyncio
import base64
import datetime as _dt
import decimal
import re
import uuid
from dataclasses import dataclass
from typing import Any, Optional, Sequence

import psycopg2
import psycopg2.extras
from psycopg2 import sql


_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*$")


def _normalize_port(port: Optional[int]) -> int:
    if port is None:
        return 5432
    if not isinstance(port, int):
        raise ValueError(f"port must be an integer or null, got {type(port).__name__}")
    if port <= 0 or port > 65535:
        raise ValueError(f"port must be in 1..65535, got {port}")
    return port


def _normalize_schema_filter(schema_filter: Optional[Sequence[str]]) -> Optional[list[str]]:
    if schema_filter is None:
        return None
    if not isinstance(schema_filter, (list, tuple)):
        raise ValueError("schema_filter must be an array of schema names or null")
    if len(schema_filter) == 0:
        return None

    out: list[str] = []
    for s in schema_filter:
        if not isinstance(s, str) or not s.strip():
            raise ValueError("schema_filter entries must be non-empty strings")
        out.append(s.strip())
    return out


def _ensure_identifier(name: str, *, what: str) -> str:
    if not isinstance(name, str) or not name.strip():
        raise ValueError(f"{what} must be a non-empty string")
    if not _IDENTIFIER_RE.match(name):
        raise ValueError(f"{what} must be a valid unquoted PostgreSQL identifier (got {name!r})")
    return name


def _ensure_non_empty_str(value: str, *, what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{what} must be a non-empty string")
    return value.strip()


def _ensure_positive_int(value: Any, *, what: str, minimum: int = 1) -> int:
    if value is None:
        raise ValueError(f"{what} must be an integer")
    if not isinstance(value, int):
        raise ValueError(f"{what} must be an integer, got {type(value).__name__}")
    if value < minimum:
        raise ValueError(f"{what} must be >= {minimum}, got {value}")
    return value


def _strip_sql_comments(sql_text: str) -> str:
    """
    Best-effort comment stripping: removes /* ... */ and -- ... end-of-line.

    Not a full SQL parser; used only for safety heuristics.
    """
    without_block = re.sub(r"/\*.*?\*/", " ", sql_text, flags=re.DOTALL)
    without_line = re.sub(r"--[^\n\r]*", " ", without_block)
    return without_line


def _validate_read_only_query(
    query: str,
    *,
    default_schema: str,
    enforce_default_schema_only: bool,
) -> None:
    if not isinstance(query, str) or not query.strip():
        raise ValueError("query must be a non-empty string")

    cleaned = _strip_sql_comments(query).strip()

    # Reject multi-statement (best-effort; semicolons in literals will also be rejected).
    if ";" in cleaned:
        raise ValueError("Only a single statement is allowed; semicolons are not permitted")

    # Must begin with SELECT or WITH (case-insensitive).
    if not re.match(r"(?is)^(select|with)\b", cleaned.lstrip()):
        raise ValueError("Only read-only SELECT/WITH statements are allowed")

    # Disallow keywords that mutate state or change settings (best-effort).
    disallowed = [
        "insert",
        "update",
        "delete",
        "upsert",
        "merge",
        "drop",
        "alter",
        "create",
        "truncate",
        "grant",
        "revoke",
        "copy",
        "call",
        "do",
        "set",
    ]
    for kw in disallowed:
        if re.search(rf"(?is)\b{re.escape(kw)}\b", cleaned):
            raise ValueError(f"Disallowed keyword detected in query: {kw.upper()}")

    if enforce_default_schema_only:
        allowed = {default_schema, "pg_catalog", "information_schema"}

        # Best-effort scan for schema-qualified relations in FROM/JOIN clauses.
        # This intentionally does not attempt to parse all SQL.
        schema_ref_re = re.compile(
            r"(?is)\b(?:from|join)\s+([A-Za-z_][A-Za-z0-9_$]*)\s*\.\s*([A-Za-z_][A-Za-z0-9_$]*)\b"
        )
        for m in schema_ref_re.finditer(cleaned):
            schema = m.group(1)
            if schema not in allowed:
                raise ValueError(
                    f"Query references schema {schema!r}, which is not allowed; "
                    f"allowed schemas are: {sorted(allowed)}"
                )


def _normalize_query_params(query_params: Optional[Sequence[Any]]) -> list[Any]:
    if query_params is None:
        return []
    if not isinstance(query_params, (list, tuple)):
        raise ValueError("query_params must be an array of positional values or null")
    return list(query_params)


def _is_system_schema(schema: str) -> bool:
    if schema in {"pg_catalog", "information_schema", "pg_toast"}:
        return True
    if schema.startswith("pg_temp") or schema.startswith("pg_toast_temp"):
        return True
    return False


def _jsonify(value: Any) -> Any:
    """
    Convert common Postgres types into JSON-serializable values.

    FastMCP will ultimately serialize tool outputs; returning raw datetimes/decimals
    may fail depending on the transport/encoder.
    """
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (decimal.Decimal, uuid.UUID)):
        return str(value)
    if isinstance(value, (bytes, bytearray)):
        return base64.b64encode(bytes(value)).decode("ascii")
    if isinstance(value, memoryview):
        return base64.b64encode(value.tobytes()).decode("ascii")
    if isinstance(value, (_dt.datetime, _dt.date, _dt.time)):
        # Keep timezone if present; ISO 8601 is broadly LLM-friendly.
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): _jsonify(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonify(v) for v in value]
    # Fallback: string representation (best-effort).
    return str(value)


def _map_psycopg2_exception(exc: Exception) -> Exception:
    # Keep it simple and avoid secrets; psycopg2 does not include password in messages.
    if isinstance(exc, psycopg2.OperationalError):
        return RuntimeError(f"PostgreSQL connection failed: {exc}")
    if isinstance(exc, psycopg2.ProgrammingError):
        return RuntimeError(f"PostgreSQL query error: {exc}")
    return exc


@dataclass(frozen=True)
class _ConnectArgs:
    host: str
    port: int
    database: str
    username: str
    password: str
    connect_timeout_seconds: int

    def to_psycopg2_kwargs(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "dbname": self.database,
            "user": self.username,
            "password": self.password,
            "connect_timeout": self.connect_timeout_seconds,
        }


class PostgresInsightsService:
    """
    Service layer for PostgreSQL read-only discovery and querying.

    Each call opens/closes its own connection; no pooling/caching.
    All connection details arrive on each method call.
    """

    _MAX_SCHEMA_ROWS: int = 5000
    _MAX_RELATION_ROWS: int = 5000
    _MAX_COLUMN_ROWS: int = 5000

    _DEFAULT_MAX_ROWS: int = 200
    _HARD_MAX_ROWS: int = 2000

    def _build_connect_args(
        self,
        *,
        host: str,
        port: Optional[int],
        database: str,
        username: str,
        password: str,
        connect_timeout_seconds: int,
    ) -> _ConnectArgs:
        host_n = _ensure_non_empty_str(host, what="host")
        db_n = _ensure_non_empty_str(database, what="database")
        user_n = _ensure_non_empty_str(username, what="username")
        if not isinstance(password, str):
            raise ValueError("password must be a string")
        port_n = _normalize_port(port)
        timeout_n = _ensure_positive_int(
            connect_timeout_seconds, what="connect_timeout_seconds", minimum=1
        )
        return _ConnectArgs(
            host=host_n,
            port=port_n,
            database=db_n,
            username=user_n,
            password=password,
            connect_timeout_seconds=timeout_n,
        )

    async def test_connection(
        self,
        host: str,
        port: Optional[int],
        database: str,
        username: str,
        password: str,
        connect_timeout_seconds: int = 10,
    ) -> dict[str, Any]:
        return await asyncio.to_thread(
            self._test_connection_sync,
            host,
            port,
            database,
            username,
            password,
            connect_timeout_seconds,
        )

    def _test_connection_sync(
        self,
        host: str,
        port: Optional[int],
        database: str,
        username: str,
        password: str,
        connect_timeout_seconds: int,
    ) -> dict[str, Any]:
        cargs = self._build_connect_args(
            host=host,
            port=port,
            database=database,
            username=username,
            password=password,
            connect_timeout_seconds=connect_timeout_seconds,
        )

        conn: Optional[psycopg2.extensions.connection] = None
        try:
            conn = psycopg2.connect(**cargs.to_psycopg2_kwargs())
            conn.set_session(readonly=True, autocommit=False)
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                _ = cur.fetchone()
            return {"reachable": True}
        except Exception as exc:
            raise _map_psycopg2_exception(exc)
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    async def list_schemas(
        self,
        host: str,
        port: Optional[int],
        database: str,
        username: str,
        password: str,
        schema_filter: Optional[Sequence[str]] = None,
    ) -> dict[str, Any]:
        return await asyncio.to_thread(
            self._list_schemas_sync,
            host,
            port,
            database,
            username,
            password,
            schema_filter,
        )

    def _list_schemas_sync(
        self,
        host: str,
        port: Optional[int],
        database: str,
        username: str,
        password: str,
        schema_filter: Optional[Sequence[str]],
    ) -> dict[str, Any]:
        cargs = self._build_connect_args(
            host=host,
            port=port,
            database=database,
            username=username,
            password=password,
            connect_timeout_seconds=10,
        )
        allow = _normalize_schema_filter(schema_filter)

        conn: Optional[psycopg2.extensions.connection] = None
        try:
            conn = psycopg2.connect(**cargs.to_psycopg2_kwargs())
            conn.set_session(readonly=True, autocommit=False)
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT schema_name
                    FROM information_schema.schemata
                    WHERE schema_name NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
                      AND schema_name NOT LIKE 'pg_temp%%'
                      AND schema_name NOT LIKE 'pg_toast_temp%%'
                    ORDER BY schema_name
                    """
                )
                rows = cur.fetchmany(self._MAX_SCHEMA_ROWS + 1)
        except Exception as exc:
            raise _map_psycopg2_exception(exc)
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

        names = [r[0] for r in rows[: self._MAX_SCHEMA_ROWS]]
        if allow is not None:
            allowed_set = set(allow)
            names = [n for n in names if n in allowed_set]

        result: dict[str, Any] = {"schemas": [{"schema": n} for n in names]}
        if len(rows) > self._MAX_SCHEMA_ROWS:
            result["truncated"] = True
            result["message"] = f"Schema list truncated to {self._MAX_SCHEMA_ROWS} results."
        else:
            result["truncated"] = False
        return result

    async def list_tables(
        self,
        host: str,
        port: Optional[int],
        database: str,
        username: str,
        password: str,
        schema_filter: Optional[Sequence[str]] = None,
        schema: str = "insights",
        include_views: bool = True,
        include_tables: bool = False,
    ) -> dict[str, Any]:
        return await asyncio.to_thread(
            self._list_tables_sync,
            host,
            port,
            database,
            username,
            password,
            schema_filter,
            schema,
            include_views,
            include_tables,
        )

    def _list_tables_sync(
        self,
        host: str,
        port: Optional[int],
        database: str,
        username: str,
        password: str,
        schema_filter: Optional[Sequence[str]],
        schema: str,
        include_views: bool,
        include_tables: bool,
    ) -> dict[str, Any]:
        schema_n = _ensure_identifier(schema, what="schema")
        allow = _normalize_schema_filter(schema_filter)
        if allow is not None and schema_n not in set(allow):
            raise ValueError(
                f"Schema {schema_n!r} is not allowed by schema_filter; allowed: {allow}"
            )
        if _is_system_schema(schema_n):
            raise ValueError(f"System schema {schema_n!r} is not allowed")

        kinds: list[str] = []
        if include_views:
            kinds.extend(["v", "m"])
        if include_tables:
            kinds.append("r")
        if not kinds:
            return {"relations": []}

        cargs = self._build_connect_args(
            host=host,
            port=port,
            database=database,
            username=username,
            password=password,
            connect_timeout_seconds=10,
        )

        conn: Optional[psycopg2.extensions.connection] = None
        try:
            conn = psycopg2.connect(**cargs.to_psycopg2_kwargs())
            conn.set_session(readonly=True, autocommit=False)
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT n.nspname AS schema,
                           c.relname AS name,
                           c.relkind AS relkind
                    FROM pg_catalog.pg_class c
                    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = %s
                      AND c.relkind = ANY(%s::"char"[])
                    ORDER BY c.relname
                    """,
                    (schema_n, kinds),
                )
                rows = cur.fetchmany(self._MAX_RELATION_ROWS + 1)
        except Exception as exc:
            raise _map_psycopg2_exception(exc)
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

        def _map_kind(k: str) -> str:
            if k == "v":
                return "view"
            if k == "m":
                return "materialized_view"
            if k == "r":
                return "table"
            return "unknown"

        rels = [
            {"schema": r[0], "name": r[1], "type": _map_kind(r[2])}
            for r in rows[: self._MAX_RELATION_ROWS]
        ]
        result: dict[str, Any] = {"relations": rels}
        if len(rows) > self._MAX_RELATION_ROWS:
            result["truncated"] = True
            result["message"] = f"Relation list truncated to {self._MAX_RELATION_ROWS} results."
        return result

    async def describe_table(
        self,
        host: str,
        port: Optional[int],
        database: str,
        username: str,
        password: str,
        schema_filter: Optional[Sequence[str]] = None,
        schema: str = "insights",
        table_name: str = "",
    ) -> dict[str, Any]:
        return await asyncio.to_thread(
            self._describe_table_sync,
            host,
            port,
            database,
            username,
            password,
            schema_filter,
            schema,
            table_name,
        )

    def _describe_table_sync(
        self,
        host: str,
        port: Optional[int],
        database: str,
        username: str,
        password: str,
        schema_filter: Optional[Sequence[str]],
        schema: str,
        table_name: str,
    ) -> dict[str, Any]:
        schema_n = _ensure_identifier(schema, what="schema")
        table_n = _ensure_identifier(table_name, what="table_name")
        allow = _normalize_schema_filter(schema_filter)
        if allow is not None and schema_n not in set(allow):
            raise ValueError(
                f"Schema {schema_n!r} is not allowed by schema_filter; allowed: {allow}"
            )
        if _is_system_schema(schema_n):
            raise ValueError(f"System schema {schema_n!r} is not allowed")

        cargs = self._build_connect_args(
            host=host,
            port=port,
            database=database,
            username=username,
            password=password,
            connect_timeout_seconds=10,
        )

        conn: Optional[psycopg2.extensions.connection] = None
        try:
            conn = psycopg2.connect(**cargs.to_psycopg2_kwargs())
            conn.set_session(readonly=True, autocommit=False)
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        column_name,
                        data_type,
                        is_nullable,
                        ordinal_position
                    FROM information_schema.columns
                    WHERE table_schema = %s
                      AND table_name = %s
                    ORDER BY ordinal_position
                    """,
                    (schema_n, table_n),
                )
                rows = cur.fetchmany(self._MAX_COLUMN_ROWS + 1)
        except Exception as exc:
            raise _map_psycopg2_exception(exc)
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

        if not rows:
            raise RuntimeError(f"relation not found: {schema_n}.{table_n}")

        cols = [
            {
                "name": r[0],
                "data_type": r[1],
                "nullable": (r[2] == "YES"),
                "ordinal_position": int(r[3]),
            }
            for r in rows[: self._MAX_COLUMN_ROWS]
        ]
        result: dict[str, Any] = {"schema": schema_n, "table": table_n, "columns": cols}
        if len(rows) > self._MAX_COLUMN_ROWS:
            result["truncated"] = True
            result["message"] = f"Column list truncated to {self._MAX_COLUMN_ROWS} results."
        return result

    async def execute_query(
        self,
        host: str,
        port: Optional[int],
        database: str,
        username: str,
        password: str,
        schema_filter: Optional[Sequence[str]] = None,
        query: str = "",
        query_params: Optional[Sequence[Any]] = None,
        max_rows: int = 200,
        default_schema: str = "insights",
        enforce_default_schema_only: bool = True,
        statement_timeout_seconds: int = 30,
    ) -> dict[str, Any]:
        return await asyncio.to_thread(
            self._execute_query_sync,
            host,
            port,
            database,
            username,
            password,
            schema_filter,
            query,
            query_params,
            max_rows,
            default_schema,
            enforce_default_schema_only,
            statement_timeout_seconds,
        )

    def _execute_query_sync(
        self,
        host: str,
        port: Optional[int],
        database: str,
        username: str,
        password: str,
        schema_filter: Optional[Sequence[str]],
        query: str,
        query_params: Optional[Sequence[Any]],
        max_rows: int,
        default_schema: str,
        enforce_default_schema_only: bool,
        statement_timeout_seconds: int,
    ) -> dict[str, Any]:
        default_schema_n = _ensure_identifier(default_schema, what="default_schema")
        if _is_system_schema(default_schema_n):
            raise ValueError(f"default_schema cannot be a system schema (got {default_schema_n!r})")

        allow = _normalize_schema_filter(schema_filter)
        if allow is not None and default_schema_n not in set(allow):
            raise ValueError(
                f"default_schema {default_schema_n!r} is not allowed by schema_filter; allowed: {allow}"
            )

        max_rows_n = _ensure_positive_int(max_rows, what="max_rows", minimum=1)
        capped_max_rows = min(max_rows_n, self._HARD_MAX_ROWS)
        capped_message: Optional[str] = None
        if max_rows_n > self._HARD_MAX_ROWS:
            capped_message = f"max_rows capped to hard limit of {self._HARD_MAX_ROWS}"

        timeout_s = _ensure_positive_int(
            statement_timeout_seconds, what="statement_timeout_seconds", minimum=1
        )

        _validate_read_only_query(
            query,
            default_schema=default_schema_n,
            enforce_default_schema_only=bool(enforce_default_schema_only),
        )

        params = _normalize_query_params(query_params)

        cargs = self._build_connect_args(
            host=host,
            port=port,
            database=database,
            username=username,
            password=password,
            connect_timeout_seconds=10,
        )

        conn: Optional[psycopg2.extensions.connection] = None
        try:
            conn = psycopg2.connect(**cargs.to_psycopg2_kwargs())
            conn.set_session(readonly=True, autocommit=False)

            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                # Apply local settings within the transaction.
                # statement_timeout expects a duration; '30s' is clear and avoids unit confusion.
                cur.execute("SET LOCAL statement_timeout = %s", (f"{timeout_s}s",))

                # Set search_path safely (identifier-quoted).
                cur.execute(
                    sql.SQL("SET LOCAL search_path TO {}, pg_catalog").format(
                        sql.Identifier(default_schema_n)
                    )
                )

                cur.execute(query, params)

                fetched = cur.fetchmany(capped_max_rows + 1)
                truncated = len(fetched) > capped_max_rows
                rows_out = fetched[:capped_max_rows]

                columns = [d.name for d in (cur.description or [])]
                # RealDictCursor rows are RealDictRow; convert to plain dict and jsonify values.
                rows = [{k: _jsonify(v) for k, v in dict(r).items()} for r in rows_out]

                result: dict[str, Any] = {
                    "columns": columns,
                    "rows": rows,
                    "row_count": len(rows),
                    "truncated": truncated,
                }
                if capped_message is not None:
                    result["message"] = capped_message
                return result
        except Exception as exc:
            raise _map_psycopg2_exception(exc)
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass