from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional, Sequence

import psycopg2
import psycopg2.extras


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
        out.append(s)
    return out


def _ensure_identifier(name: str, *, what: str) -> str:
    if not isinstance(name, str) or not name.strip():
        raise ValueError(f"{what} must be a non-empty string")
    if not _IDENTIFIER_RE.match(name):
        raise ValueError(
            f"{what} must be a valid unquoted PostgreSQL identifier (got {name!r})"
        )
    return name


def _strip_sql_comments(sql: str) -> str:
    """
    Best-effort comment stripping: removes /* ... */ and -- ... end-of-line.

    This is not a full SQL parser and may be confused by comments inside string
    literals. It is used only for safety heuristics (read-only validation).
    """
    # Remove block comments.
    without_block = re.sub(r"/\*.*?\*/", " ", sql, flags=re.DOTALL)
    # Remove line comments.
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

    # Best-effort: strip comments, then validate statement shape.
    cleaned = _strip_sql_comments(query).strip()

    # Reject multi-statement.
    if ";" in cleaned:
        raise ValueError("Only a single statement is allowed; semicolons are not permitted")

    # Must begin with SELECT or WITH (case-insensitive).
    cleaned_l = cleaned.lstrip()
    if not re.match(r"(?is)^(select|with)\b", cleaned_l):
        raise ValueError("Only read-only SELECT/WITH statements are allowed")

    # Reject obviously mutating/admin keywords (best-effort; may false-positive in string literals).
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
        # Best-effort: scan for FROM/JOIN <schema>.<rel> references (unquoted identifiers).
        # This reduces false positives compared to scanning for any "<token>." which
        # would match table aliases (e.g., "t.col").
        allowed = {default_schema, "pg_catalog", "information_schema"}
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

    All connection details arrive on every call (host, port, database, username, password).
    No global connections are cached; each call opens/closes its own resources.
    """

    # Internal safety caps for discovery endpoints (tools don't expose these knobs).
    _MAX_SCHEMA_ROWS: int = 5000
    _MAX_RELATION_ROWS: int = 5000

    # Internal safety cap to prevent extremely large payloads.
    _HARD_MAX_ROWS: int = 2000

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
        conn = None
        try:
            conn = psycopg2.connect(**cargs.to_psycopg2_kwargs())
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                _ = cur.fetchone()
            return {"reachable": True}
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    # Best-effort close; do not mask original error.
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
        schema_filter: Optional[Sequence[str]] = None,
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
        conn = None
        try:
            conn = psycopg2.connect(**cargs.to_psycopg2_kwargs())
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
            result["message"] = (
                f"Schema list truncated to {self._MAX_SCHEMA_ROWS} results."
            )
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
        schema = _ensure_identifier(schema, what="schema")
        allow = _normalize_schema_filter(schema_filter)
        if allow is not None and schema not in set(allow):
            raise ValueError(
                f"Schema {schema!r} is not allowed by schema_filter; allowed: {allow}"
            )

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

        conn = None
        try:
            conn = psycopg2.connect(**cargs.to_psycopg2_kwargs())
            with conn.cursor() as cur:
                # Use pg_catalog for accurate relkind classification.
                cur.execute(
                    """
                    SELECT n.nspname AS schema,
                           c.relname AS name,
                           c.relkind AS relkind
                    FROM pg_catalog.pg_class c
                    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = %s
                      AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
                      AND n.nspname NOT LIKE 'pg_temp%%'
                      AND n.nspname NOT LIKE 'pg_toast_temp%%'
                      AND c.relkind = ANY(%s)
                    ORDER BY c.relname
                    """,
                    (schema, kinds),
                )
                rows = cur.fetchmany(self._MAX_RELATION_ROWS + 1)
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
            result["message"] = (
                f"Relation list truncated to {self._MAX_RELATION_ROWS} results."
            )
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
        schema = _ensure_identifier(schema, what="schema")
        table_name = _ensure_identifier(table_name, what="table_name")

        allow = _normalize_schema_filter(schema_filter)
        if allow is not None and schema not in set(allow):
            raise ValueError(
                f"Schema {schema!r} is not allowed by schema_filter; allowed: {allow}"
            )

        cargs = self._build_connect_args(
            host=host,
            port=port,
            database=database,
            username=username,
            password=password,
            connect_timeout_seconds=10,
        )

        conn = None
        rows: list[tuple[Any, ...]] = []
        try:
            conn = psycopg2.connect(**cargs.to_psycopg2_kwargs())
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
                    (schema, table_name),
                )
                rows = cur.fetchall()
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

        if not rows:
            raise LookupError(f"Table/view not found or not visible: {schema}.{table_name}")

        cols = [
            {
                "name": r[0],
                "data_type": r[1],
                "nullable": (r[2] == "YES"),
                "ordinal_position": int(r[3]),
            }
            for r in rows
        ]
        return {"schema": schema, "table": table_name, "columns": cols}

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
        default_schema = _ensure_identifier(default_schema, what="default_schema")

        allow = _normalize_schema_filter(schema_filter)
        if allow is not None and default_schema not in set(allow):
            raise ValueError(
                f"default_schema {default_schema!r} is not allowed by schema_filter; allowed: {allow}"
            )

        if not isinstance(max_rows, int):
            raise ValueError("max_rows must be an integer")
        if max_rows <= 0:
            raise ValueError("max_rows must be > 0")

        effective_max_rows = min(max_rows, self._HARD_MAX_ROWS)
        if not isinstance(statement_timeout_seconds, int):
            raise ValueError("statement_timeout_seconds must be an integer")
        if statement_timeout_seconds <= 0:
            raise ValueError("statement_timeout_seconds must be > 0")

        _validate_read_only_query(
            query,
            default_schema=default_schema,
            enforce_default_schema_only=bool(enforce_default_schema_only),
        )

        params: Sequence[Any]
        if query_params is None:
            params = ()
        else:
            if not isinstance(query_params, (list, tuple)):
                raise ValueError("query_params must be an array of positional parameters or null")
            params = query_params

        cargs = self._build_connect_args(
            host=host,
            port=port,
            database=database,
            username=username,
            password=password,
            connect_timeout_seconds=10,
        )

        conn = None
        try:
            conn = psycopg2.connect(**cargs.to_psycopg2_kwargs())
            # Ensure transactional context for SET LOCAL.
            with conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    # statement_timeout expects milliseconds.
                    cur.execute(
                        "SET LOCAL statement_timeout = %s",
                        (int(statement_timeout_seconds * 1000),),
                    )
                    # Make default_schema first in search_path, include pg_catalog.
                    cur.execute(
                        "SET LOCAL search_path = %s",
                        (f"{default_schema}, pg_catalog",),
                    )

                    cur.execute(query, params)

                    # Fetch max_rows + 1 to detect truncation.
                    fetched = cur.fetchmany(effective_max_rows + 1)
                    truncated = len(fetched) > effective_max_rows
                    trimmed = fetched[:effective_max_rows]

                    # Column order comes from cursor.description.
                    columns: list[str] = []
                    if cur.description:
                        columns = [d.name for d in cur.description]

                    rows = [dict(r) for r in trimmed]

                    result: dict[str, Any] = {
                        "columns": columns,
                        "rows": rows,
                        "row_count": len(rows),
                        "truncated": truncated,
                    }
                    if effective_max_rows != max_rows:
                        result["message"] = (
                            f"Requested max_rows={max_rows} clamped to {effective_max_rows}."
                        )
                        result["effective_max_rows"] = effective_max_rows
                    return result
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

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
        if not isinstance(host, str) or not host.strip():
            raise ValueError("host must be a non-empty string")
        if not isinstance(database, str) or not database.strip():
            raise ValueError("database must be a non-empty string")
        if not isinstance(username, str) or not username.strip():
            raise ValueError("username must be a non-empty string")
        if not isinstance(password, str):
            raise ValueError("password must be a string")
        if not isinstance(connect_timeout_seconds, int):
            raise ValueError("connect_timeout_seconds must be an integer")
        if connect_timeout_seconds <= 0:
            raise ValueError("connect_timeout_seconds must be > 0")

        return _ConnectArgs(
            host=host,
            port=_normalize_port(port),
            database=database,
            username=username,
            password=password,
            connect_timeout_seconds=connect_timeout_seconds,
        )


service = PostgresInsightsService()