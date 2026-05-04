"""LearnAI compatibility shim for the mem0 REST API.

The LearnAI client (`app/src/memory/mem0.ts` in oznakash/learnai) was written
against an earlier shape of the mem0 REST surface that uses /v1/memories/
paths and `Authorization: Bearer <key>` for auth. The current server exposes
those endpoints under different paths (`/memories`, `/search`) and accepts
the static admin key only via the `X-API-Key` header.

This router translates between the two without requiring a LearnAI-side
change. It maps:

  GET    /health                  -> 200 {"status": "ok"} (no auth)
  POST   /v1/memories/            -> POST /memories
  GET    /v1/memories/?user_id=.. -> GET  /memories?user_id=..
  POST   /v1/memories/search/     -> POST /search   (limit -> top_k)
  PUT    /v1/memories/{id}/       -> PUT  /memories/{id}
  DELETE /v1/memories/{id}/       -> DELETE /memories/{id}
  DELETE /v1/memories/?user_id=.. -> DELETE /memories?user_id=..

Auth: the underlying `verify_auth` dependency is unchanged; this shim
relies on the companion change in `server/auth.py` that lets the static
ADMIN_API_KEY be presented as a Bearer token (which is what LearnAI sends).

Trailing slashes matter: the FastAPI app is constructed with
`redirect_slashes=False`, so each route registers the exact path LearnAI
calls.
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from auth import verify_auth
from errors import upstream_error
from server_state import get_memory_instance


router = APIRouter()


class _Message(BaseModel):
    role: str = Field(..., description="Role of the message (user or assistant).")
    content: str = Field(..., description="Message content.")


class _MemoryCreate(BaseModel):
    messages: List[_Message]
    user_id: Optional[str] = None
    agent_id: Optional[str] = None
    run_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    infer: Optional[bool] = None


class _MemoryUpdate(BaseModel):
    text: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    category: Optional[str] = None


class _SearchRequest(BaseModel):
    query: str
    user_id: Optional[str] = None
    run_id: Optional[str] = None
    agent_id: Optional[str] = None
    filters: Optional[Dict[str, Any]] = None
    limit: Optional[int] = None
    top_k: Optional[int] = None
    threshold: Optional[float] = None


_RESERVED_PAYLOAD_KEYS = {
    "data",
    "user_id",
    "agent_id",
    "run_id",
    "hash",
    "created_at",
    "updated_at",
}


def _serialize_memory(row: Any) -> Dict[str, Any]:
    payload = getattr(row, "payload", None) or {}
    return {
        "id": getattr(row, "id", None),
        "memory": payload.get("data"),
        "user_id": payload.get("user_id"),
        "agent_id": payload.get("agent_id"),
        "run_id": payload.get("run_id"),
        "hash": payload.get("hash"),
        "metadata": {k: v for k, v in payload.items() if k not in _RESERVED_PAYLOAD_KEYS},
        "created_at": payload.get("created_at"),
        "updated_at": payload.get("updated_at"),
    }


@router.get("/health", summary="Health probe (LearnAI compat)", include_in_schema=True)
def health() -> Dict[str, str]:
    """No-auth health probe.

    LearnAI's Admin Console hits this before any authed call to confirm that
    mem0 is reachable. Returns a tiny JSON body so the client's content-type
    check passes; the body content itself is ignored by the client.
    """
    return {"status": "ok"}


@router.post("/v1/memories/", summary="Add memory (LearnAI compat)")
def v1_add_memory(memory_create: _MemoryCreate, _auth=Depends(verify_auth)):
    if not any([memory_create.user_id, memory_create.agent_id, memory_create.run_id]):
        raise HTTPException(
            status_code=400,
            detail="At least one identifier (user_id, agent_id, run_id) is required.",
        )
    params = {
        k: v
        for k, v in memory_create.model_dump().items()
        if v is not None and k != "messages"
    }
    try:
        response = get_memory_instance().add(
            messages=[m.model_dump() for m in memory_create.messages], **params
        )
        return JSONResponse(content=response)
    except Exception:
        raise upstream_error()


@router.get("/v1/memories/", summary="List memories (LearnAI compat)")
def v1_list_memories(
    user_id: Optional[str] = None,
    run_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    limit: Optional[int] = None,
    category: Optional[str] = None,
    _auth=Depends(verify_auth),
):
    """List memories for the given identifier.

    `category` is accepted for client compatibility but not pushed to the
    underlying store -- mem0's REST API doesn't surface a category filter at
    the route level. Clients that need category filtering can filter the
    returned `metadata.category` field client-side. (LearnAI does this.)
    """
    try:
        if not any([user_id, run_id, agent_id]):
            results = get_memory_instance().vector_store.list(top_k=limit or 1000)
            rows = (
                results[0]
                if results and isinstance(results, list) and isinstance(results[0], list)
                else results or []
            )
            return {"results": [_serialize_memory(row) for row in rows]}

        filters = {
            k: v
            for k, v in {"user_id": user_id, "run_id": run_id, "agent_id": agent_id}.items()
            if v is not None
        }
        return get_memory_instance().get_all(filters=filters)
    except Exception:
        raise upstream_error()


def _build_search_kwargs(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Translate a `_SearchRequest`-shaped dict into the kwargs expected
    by `Memory.search()`. Pure / no I/O so the contract is unit-testable
    without FastAPI + SQLAlchemy + mem0's import chain.

    Two non-trivial behaviors pinned here:

    1. **`limit` → `top_k`.** The LearnAI client sends `limit`; mem0
       expects `top_k`. Explicit `top_k` (if supplied) wins.
    2. **Entity ids must live inside `filters={...}`.** Upstream mem0's
       `_reject_top_level_entity_params` guard refuses `user_id`,
       `run_id`, `agent_id` as top-level kwargs. Hoist them into
       `filters` while preserving any client-supplied filter entries —
       client filters win on key collision.
    """
    params = {
        k: v
        for k, v in payload.items()
        if v is not None and k not in ("query", "limit")
    }
    limit = payload.get("limit")
    if limit is not None and "top_k" not in params:
        params["top_k"] = limit
    entity_filters = {
        k: params.pop(k)
        for k in ("user_id", "run_id", "agent_id")
        if k in params
    }
    if entity_filters:
        existing = params.get("filters") or {}
        params["filters"] = {**entity_filters, **existing}
    return params


@router.post("/v1/memories/search/", summary="Search memories (LearnAI compat)")
def v1_search_memories(search_req: _SearchRequest, _auth=Depends(verify_auth)):
    """Semantic search.

    See `_build_search_kwargs` for the limit→top_k mapping and the
    entity-id-hoisting behavior.
    """
    try:
        kwargs = _build_search_kwargs(search_req.model_dump())
        return get_memory_instance().search(query=search_req.query, **kwargs)
    except Exception:
        raise upstream_error()


@router.put("/v1/memories/{memory_id}/", summary="Update memory (LearnAI compat)")
def v1_update_memory(
    memory_id: str, updated_memory: _MemoryUpdate, _auth=Depends(verify_auth)
):
    if updated_memory.text is None:
        raise HTTPException(status_code=400, detail="text is required.")
    metadata: Optional[Dict[str, Any]] = (
        dict(updated_memory.metadata) if updated_memory.metadata else None
    )
    if updated_memory.category is not None:
        metadata = metadata or {}
        metadata["category"] = updated_memory.category
    try:
        return get_memory_instance().update(
            memory_id=memory_id, data=updated_memory.text, metadata=metadata
        )
    except Exception:
        raise upstream_error()


@router.delete("/v1/memories/{memory_id}/", summary="Delete a memory (LearnAI compat)")
def v1_delete_memory(memory_id: str, _auth=Depends(verify_auth)):
    try:
        get_memory_instance().delete(memory_id=memory_id)
        return {"message": "Memory deleted successfully"}
    except Exception:
        raise upstream_error()


@router.delete("/v1/memories/", summary="Wipe memories for an identifier (LearnAI compat)")
def v1_delete_all_memories(
    user_id: Optional[str] = None,
    run_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    _auth=Depends(verify_auth),
):
    if not any([user_id, run_id, agent_id]):
        raise HTTPException(status_code=400, detail="At least one identifier is required.")
    try:
        params = {
            k: v
            for k, v in {"user_id": user_id, "run_id": run_id, "agent_id": agent_id}.items()
            if v is not None
        }
        get_memory_instance().delete_all(**params)
        return {"message": "All relevant memories deleted"}
    except Exception:
        raise upstream_error()
