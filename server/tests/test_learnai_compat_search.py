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

Implementation note: the fix lives in a pure helper
`_build_search_kwargs` so the contract is unit-testable without
dragging in FastAPI / SQLAlchemy / mem0 itself. We extract it via a
text snippet from the source file rather than `import routers.learnai_compat`
so this test can't pollute `sys.modules` for the other smoke tests
running in the same pytest process.
"""

from __future__ import annotations

import os
from typing import Any, Callable, Dict


def _extract_helper() -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    """Slice `_build_search_kwargs` out of the router source and exec
    it in a fresh namespace. Keeps the test environment minimal — no
    fastapi, no sqlalchemy, no mem0 needed."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src_path = os.path.join(here, "routers", "learnai_compat.py")
    with open(src_path, "r", encoding="utf-8") as f:
        src = f.read()
    start_marker = "def _build_search_kwargs"
    if start_marker not in src:
        raise RuntimeError(
            "_build_search_kwargs helper missing from "
            "routers/learnai_compat.py — has the fix been reverted?"
        )
    start = src.index(start_marker)
    # Helper ends at the next top-level `def ` or `@router` directive.
    end = len(src)
    for marker in ("\n@router", "\ndef "):
        idx = src.find(marker, start + len(start_marker))
        if idx >= 0 and idx < end:
            end = idx
    snippet = "from typing import Any, Dict\n" + src[start:end]
    ns: Dict[str, Any] = {}
    exec(compile(snippet, src_path, "exec"), ns)  # noqa: S102 — controlled test snippet.
    return ns["_build_search_kwargs"]


_build = _extract_helper()


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
