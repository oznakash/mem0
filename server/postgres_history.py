"""Postgres-backed drop-in for mem0's SQLiteManager.

Why this exists: mem0's stock SQLiteManager writes its audit trail and
message buffer to a single SQLite file at HISTORY_DB_PATH. On hosting
platforms that don't expose persistent volumes (Cloud-Claude, etc.),
that file lives on the container's overlay filesystem and dies on
every rebuild — so memory-edit history vanishes on every deploy.

Since we already have a persistent Postgres (the pgvector service that
holds the actual memories), we redirect mem0's history + messages into
that same Postgres. Net result: mem0 stops needing any persistent
filesystem at all.

The class deliberately matches the public interface of mem0's
SQLiteManager line-for-line (see mem0/memory/storage.py) so it drops
in via attribute swap on the live `Memory` instance — no upstream fork,
no monkey-patch beyond `instance.db = PostgresHistoryManager(...)`.

The schema is created by alembic migration 008 (mem0_history,
mem0_messages). Indexes on memory_id and (session_scope, created_at)
match the only lookup paths the Memory class actually uses.
"""

from __future__ import annotations

import logging
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import psycopg
from psycopg.rows import dict_row


def _utcnow_iso() -> str:
    """ISO-8601 UTC timestamp matching mem0's SQLiteManager format."""
    return datetime.now(timezone.utc).isoformat()


class PostgresHistoryManager:
    """Drop-in replacement for mem0.memory.storage.SQLiteManager backed
    by Postgres. Public surface matches the SQLiteManager class verbatim
    so a `memory_instance.db = PostgresHistoryManager(...)` swap is
    transparent to the rest of mem0.

    Connections are held in a per-instance pool of one (thread-local
    via a lock around the cursor) — mem0's call sites are sparse, so a
    full pool would be overkill.
    """

    def __init__(
        self,
        host: str,
        port: int,
        dbname: str,
        user: str,
        password: str,
        connect_timeout: int = 10,
    ) -> None:
        self._dsn = (
            f"host={host} port={port} dbname={dbname} user={user} "
            f"password={password} connect_timeout={connect_timeout}"
        )
        self._lock = threading.Lock()
        # Connect lazily so a transient Postgres outage at boot doesn't
        # block server startup; first call to add_history / save_messages
        # will reconnect.
        self._conn: Optional[psycopg.Connection] = None
        try:
            self._conn = psycopg.connect(self._dsn, autocommit=True)
            logging.info("PostgresHistoryManager: connected to %s/%s", host, dbname)
        except Exception as e:
            logging.warning("PostgresHistoryManager: deferred connect (%s)", e)

    # ---------- internals ----------

    def _ensure_conn(self) -> psycopg.Connection:
        """Best-effort get a live connection. Reconnects if dead."""
        if self._conn is not None:
            try:
                with self._conn.cursor() as cur:
                    cur.execute("SELECT 1")
                return self._conn
            except Exception:
                try:
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None
        self._conn = psycopg.connect(self._dsn, autocommit=True)
        return self._conn

    # ---------- mem0 SQLiteManager-compatible methods ----------

    def _migrate_history_table(self) -> None:
        # No-op: alembic 008 migration is the source of truth for the schema.
        return

    def _create_history_table(self) -> None:
        # No-op — alembic 008 created the table at boot.
        return

    def _create_messages_table(self) -> None:
        # No-op — alembic 008 created the table at boot.
        return

    def add_history(
        self,
        memory_id: str,
        old_memory: Optional[str],
        new_memory: Optional[str],
        event: str,
        *,
        created_at: Optional[str] = None,
        updated_at: Optional[str] = None,
        is_deleted: int = 0,
        actor_id: Optional[str] = None,
        role: Optional[str] = None,
    ) -> None:
        with self._lock:
            conn = self._ensure_conn()
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO mem0_history (
                        id, memory_id, old_memory, new_memory, event,
                        created_at, updated_at, is_deleted, actor_id, role
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        str(uuid.uuid4()),
                        memory_id,
                        old_memory,
                        new_memory,
                        event,
                        created_at or _utcnow_iso(),
                        updated_at or _utcnow_iso(),
                        int(is_deleted or 0),
                        actor_id,
                        role,
                    ),
                )

    def batch_add_history(self, records: List[Dict[str, Any]]) -> None:
        if not records:
            return
        with self._lock:
            conn = self._ensure_conn()
            with conn.cursor() as cur:
                cur.executemany(
                    """
                    INSERT INTO mem0_history (
                        id, memory_id, old_memory, new_memory, event,
                        created_at, updated_at, is_deleted, actor_id, role
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    [
                        (
                            r.get("id") or str(uuid.uuid4()),
                            r.get("memory_id"),
                            r.get("old_memory"),
                            r.get("new_memory"),
                            r.get("event"),
                            r.get("created_at") or _utcnow_iso(),
                            r.get("updated_at") or _utcnow_iso(),
                            int(r.get("is_deleted") or 0),
                            r.get("actor_id"),
                            r.get("role"),
                        )
                        for r in records
                    ],
                )

    def get_history(self, memory_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._ensure_conn()
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT id, memory_id, old_memory, new_memory, event,
                           created_at, updated_at, is_deleted, actor_id, role
                    FROM mem0_history
                    WHERE memory_id = %s
                    ORDER BY created_at ASC, updated_at ASC
                    """,
                    (memory_id,),
                )
                return list(cur.fetchall())

    def save_messages(self, messages: List[Dict[str, Any]], session_scope: str) -> None:
        if not messages:
            return
        with self._lock:
            conn = self._ensure_conn()
            with conn.cursor() as cur:
                cur.executemany(
                    """
                    INSERT INTO mem0_messages (id, session_scope, role, content, name, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    [
                        (
                            str(uuid.uuid4()),
                            session_scope,
                            m.get("role"),
                            m.get("content"),
                            m.get("name"),
                            m.get("created_at") or _utcnow_iso(),
                        )
                        for m in messages
                    ],
                )

    def get_last_messages(self, session_scope: str, limit: int = 10) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._ensure_conn()
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT role, content, name, created_at
                    FROM (
                        SELECT role, content, name, created_at
                        FROM mem0_messages
                        WHERE session_scope = %s
                        ORDER BY created_at DESC
                        LIMIT %s
                    ) t
                    ORDER BY created_at ASC
                    """,
                    (session_scope, int(limit)),
                )
                return list(cur.fetchall())

    def reset(self) -> None:
        with self._lock:
            conn = self._ensure_conn()
            with conn.cursor() as cur:
                cur.execute("TRUNCATE TABLE mem0_history")
                cur.execute("TRUNCATE TABLE mem0_messages")

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                finally:
                    self._conn = None


def attach_postgres_history(memory_instance: Any, *, host: str, port: int, dbname: str, user: str, password: str) -> None:
    """Swap the SQLiteManager on a live mem0 Memory instance.

    The previous backend (a SQLiteManager pointed at HISTORY_DB_PATH)
    is closed first to release the file handle. After this call, every
    add_history / get_history / save_messages / reset / etc. flows
    through Postgres.
    """
    new_db = PostgresHistoryManager(host=host, port=port, dbname=dbname, user=user, password=password)
    old = getattr(memory_instance, "db", None)
    memory_instance.db = new_db
    if old is not None and hasattr(old, "close"):
        try:
            old.close()
        except Exception as e:
            logging.warning("Failed to close prior history DB cleanly: %s", e)
    logging.info("PostgresHistoryManager attached to mem0 Memory instance")
