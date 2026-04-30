"""Build smoke: PostgresHistoryManager matches mem0's SQLiteManager surface.

The whole point of PostgresHistoryManager is that it drops in via
`memory_instance.db = PostgresHistoryManager(...)` at runtime. If
mem0 ever changes the SQLiteManager interface (renames a method, adds
a required keyword arg) and we don't follow, the swap silently fails
in production — calls would either crash or hit the SQLite default.

This test does an introspection-only signature check: every public
method present on mem0's SQLiteManager must exist on
PostgresHistoryManager with a compatible signature. We compare argument
names so adding/removing required kwargs is caught.

No DB needed, no network, sub-second.
"""

from __future__ import annotations

import inspect
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if HERE not in sys.path:
    sys.path.insert(0, HERE)


def _public_methods(cls):
    """Public callable attributes that aren't dunder helpers."""
    return {
        name: getattr(cls, name)
        for name in dir(cls)
        if not name.startswith("_")
        and callable(getattr(cls, name, None))
    }


def test_postgres_history_manager_implements_sqlite_manager_surface():
    try:
        from mem0.memory.storage import SQLiteManager  # type: ignore[import-not-found]
    except Exception as e:
        # mem0 lib unavailable in the pytest env (e.g. a slim image
        # without optional deps). Skip rather than fail the build —
        # the runtime container has it, that's where the real check
        # happens.
        import pytest

        pytest.skip(f"mem0 not importable in this env: {e}")
        return  # for type checkers

    from postgres_history import PostgresHistoryManager  # type: ignore

    sqlite_methods = _public_methods(SQLiteManager)
    postgres_methods = _public_methods(PostgresHistoryManager)

    # Every public method on SQLiteManager must exist on the Postgres adapter.
    missing = [name for name in sqlite_methods if name not in postgres_methods]
    assert not missing, (
        f"PostgresHistoryManager is missing methods that SQLiteManager has: {missing}. "
        "If mem0 added a method, mirror it on PostgresHistoryManager."
    )

    # For each shared method, parameter names should match (positional + keyword).
    for name in sqlite_methods:
        if name not in postgres_methods:
            continue
        try:
            sig_sqlite = inspect.signature(sqlite_methods[name])
            sig_pg = inspect.signature(postgres_methods[name])
        except (TypeError, ValueError):
            continue  # builtin/C function we can't introspect; skip
        sqlite_params = [p.name for p in sig_sqlite.parameters.values() if p.name != "self"]
        pg_params = [p.name for p in sig_pg.parameters.values() if p.name != "self"]
        assert sqlite_params == pg_params, (
            f"Param names diverged for `{name}`. "
            f"SQLiteManager: {sqlite_params}; PostgresHistoryManager: {pg_params}"
        )
