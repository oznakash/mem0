"""Regression: /v1/memories/search/ wraps entity ids in filters{}.

The bug: the LearnAI client sends `user_id` (and optionally `run_id`,
`agent_id`) as top-level fields on the search request body. The route
used to spread them as kwargs into `Memory.search(...)`. Upstream mem0
now rejects top-level entity kwargs:

    ValueError: Top-level entity parameters frozenset({'user_id'})
    are not supported in search(). Use filters={'user_id': '...'}
    instead.

Result on the live service: every memory-search call returned 500
("Upstream provider error"). This test pins the fix — entity ids must
land in `kwargs["filters"]`, never as top-level kwargs.

The fix is in a pure helper `_build_search_kwargs` so we can unit-test
the translation without dragging in the FastAPI app, sqlalchemy, or
mem0 itself.
"""

from __future__ import annotations

import importlib
import os
import sys
from types import ModuleType
from unittest.mock import MagicMock

# Set env vars + sys.path before importing.
os.environ.setdefault("AUTH_DISABLED", "true")
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if HERE not in sys.path:
    sys.path.insert(0, HERE)


def _load_helper():
    """Import the helper while stubbing its heavy deps so the import
    works in a minimal venv."""
    # Stub `auth.verify_auth` (pulled by the router on import)
    auth_stub = ModuleType("auth")
    auth_stub.verify_auth = lambda: None  # type: ignore[attr-defined]
    sys.modules.setdefault("auth", auth_stub)
    # Stub `mem0_compat.get_memory_instance` if used; the router imports
    # `mem0_compat` so we provide a minimal module.
    mem0_compat_stub = ModuleType("mem0_compat")
    mem0_compat_stub.get_memory_instance = lambda: MagicMock()  # type: ignore[attr-defined]
    sys.modules.setdefault("mem0_compat", mem0_compat_stub)
    # Stub `errors`
    errors_stub = ModuleType("errors")

    class _Up(Exception):
        pass

    errors_stub.upstream_error = _Up  # type: ignore[attr-defined]
    sys.modules.setdefault("errors", errors_stub)
    # Now import the module — but only pull the helper out, ignore the
    # router-level FastAPI/SQLAlchemy plumbing.
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "_compat_for_test",
        os.path.join(HERE, "routers", "learnai_compat.py"),
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception:
        # Some module-level imports may fail in the minimal venv. The
        # helper is still re-exposable via its source — fall back to an
        # exec of just the helper definition.
        with open(os.path.join(HERE, "routers", "learnai_compat.py")) as f:
            src = f.read()
        # Snip from `def _build_search_kwargs` to the next `def `.
        start = src.index("def _build_search_kwargs")
        end = src.index("\n@router", start)
        snippet = (
            "from typing import Any, Dict\n" + src[start:end]
        )
        ns: dict = {}
        exec(snippet, ns)  # noqa: S102 — controlled snippet, test-only.
        return ns["_build_search_kwargs"]
    return mod._build_search_kwargs


_build = _load_helper()


def test_user_id_is_promoted_into_filters():
    out = _build({"query": "what did I learn", "user_id": "alex@gmail.com"})
    assert "user_id" not in out, "user_id must not be a top-level kwarg"
    assert out.get("filters") == {"user_id": "alex@gmail.com"}


def test_run_id_and_agent_id_are_also_promoted():
    out = _build(
        {
            "query": "anything",
            "user_id": "u@x.com",
            "run_id": "r-1",
            "agent_id": "a-1",
        }
    )
    assert "user_id" not in out
    assert "run_id" not in out
    assert "agent_id" not in out
    assert out["filters"] == {
        "user_id": "u@x.com",
        "run_id": "r-1",
        "agent_id": "a-1",
    }


def test_client_supplied_filters_win_on_key_collision():
    # Defensive: a future client that sends both top-level user_id AND a
    # filters dict with a different user_id should land on the explicit
    # filter intent, not the legacy top-level value.
    out = _build(
        {
            "query": "q",
            "user_id": "legacy@x.com",
            "filters": {"user_id": "explicit@x.com"},
        }
    )
    assert out["filters"] == {"user_id": "explicit@x.com"}


def test_no_entity_ids_means_no_filters_key():
    out = _build({"query": "q"})
    assert "filters" not in out


def test_limit_maps_to_top_k():
    out = _build({"query": "q", "user_id": "u@x.com", "limit": 7})
    assert out.get("top_k") == 7
    assert "limit" not in out


def test_explicit_top_k_wins_over_limit():
    out = _build({"query": "q", "user_id": "u@x.com", "limit": 7, "top_k": 12})
    assert out["top_k"] == 12
