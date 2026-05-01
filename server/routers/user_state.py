"""Per-user state blob — the cross-device sync endpoint for the LearnAI SPA.

The SPA holds PlayerState (XP, streak, profile, history, badges,
tasks, prefs) in browser localStorage. That breaks the moment the
same user signs in on a phone or a laptop. This module persists a
single opaque JSON blob per email, so the SPA can:

  * GET /v1/state           → load the blob on sign-in / app boot
  * PUT /v1/state           → write the blob (debounced) on any mutation
  * DELETE /v1/state        → wipe (used by "wipe everything" UX)

All three require a session JWT (the email comes from the token's
`email` claim — clients can't pretend to be someone else). Other auth
types (admin_api_key, dashboard JWT, X-API-Key) are rejected with
401 here even though they pass `verify_auth` elsewhere — the blob is
deliberately tied to a real signed-in user, not an operator break-glass.

The blob is opaque to the server — the SPA decides its shape — so
server-side schema changes don't require a coordinated client release.
Size cap is enforced at the router (256 KB); bigger payloads return 413.
"""

import json
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from auth import verify_auth
from db import get_db
from models import UserState
from schemas import MessageResponse


router = APIRouter(prefix="/v1", tags=["state"])

# 256 KB. PlayerState with ~1000 history rows + tasks + everything else is
# closer to ~80 KB; this leaves headroom without inviting abuse.
MAX_BLOB_BYTES = 256 * 1024


def _require_session_email(request: Request) -> str:
    """Pull the email out of the session JWT claim, or 401.

    Other auth types (admin_api_key, bearer/access JWT, api_key) are
    rejected — /v1/state is per-user and only makes sense with a real
    signed-in identity.
    """
    auth_type = getattr(request.state, "auth_type", "none")
    session_user = getattr(request.state, "session_user", None)
    if auth_type != "google_session" or not isinstance(session_user, dict):
        raise HTTPException(
            status_code=401,
            detail="/v1/state requires a Google session (POST /auth/google first).",
        )
    email = (session_user.get("email") or "").lower().strip()
    if not email:
        raise HTTPException(status_code=401, detail="Session token is missing the email claim.")
    return email


class StateResponse(BaseModel):
    blob: dict[str, Any] = Field(default_factory=dict, description="Opaque per-user JSON blob")
    updated_at: Optional[datetime] = Field(None, description="Server-side last write time, or null on first read")


class StateWriteRequest(BaseModel):
    blob: dict[str, Any] = Field(..., description="Opaque per-user JSON blob to persist")


@router.get("/state", response_model=StateResponse, summary="Load this session's user state")
def get_state(request: Request, _auth=Depends(verify_auth), db: Session = Depends(get_db)):
    email = _require_session_email(request)
    row = db.scalar(select(UserState).where(UserState.email == email))
    if row is None:
        # First read for this user — give them an empty blob (clients
        # treat this as "no remote state yet, keep whatever's local").
        return StateResponse(blob={}, updated_at=None)
    return StateResponse(blob=row.blob or {}, updated_at=row.updated_at)


@router.put("/state", response_model=StateResponse, summary="Replace this session's user state")
def put_state(
    payload: StateWriteRequest,
    request: Request,
    _auth=Depends(verify_auth),
    db: Session = Depends(get_db),
):
    email = _require_session_email(request)

    # Cap payload size — JSONB can technically hold gigabytes, but a runaway
    # client with no debounce would chew through Postgres + bandwidth fast.
    # 256 KB is plenty for PlayerState with thousands of history rows.
    serialized = json.dumps(payload.blob, separators=(",", ":"))
    if len(serialized.encode("utf-8")) > MAX_BLOB_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"User-state blob exceeds {MAX_BLOB_BYTES // 1024} KB cap.",
        )

    row = db.scalar(select(UserState).where(UserState.email == email))
    if row is None:
        row = UserState(email=email, blob=payload.blob)
        db.add(row)
    else:
        row.blob = payload.blob
        # `updated_at = onupdate=_utcnow` covers the timestamp.
    db.commit()
    db.refresh(row)
    return StateResponse(blob=row.blob or {}, updated_at=row.updated_at)


@router.delete("/state", response_model=MessageResponse, summary="Wipe this session's user state")
def delete_state(request: Request, _auth=Depends(verify_auth), db: Session = Depends(get_db)):
    email = _require_session_email(request)
    row = db.scalar(select(UserState).where(UserState.email == email))
    if row is not None:
        db.delete(row)
        db.commit()
    return MessageResponse(message="User state wiped.")


# -- Admin: cross-user introspection ---------------------------------------
# user_state is the canonical "real users" table — every Google sign-in
# that does anything in the SPA writes a row here via the cross-device
# sync. Admin Analytics in the SPA was previously reading user counts off
# social-svc, which only sees users who hit the (often-disabled) social
# pipeline — so a populated platform showed `1 user`. This endpoint is
# the missing source of truth.

class AdminUserSummary(BaseModel):
    email: str
    updated_at: Optional[datetime]
    xp: int = 0
    streak: int = 0


class AdminUsersResponse(BaseModel):
    count: int = Field(..., description="Total rows in user_state.")
    recent: list[AdminUserSummary] = Field(
        default_factory=list,
        description="Most-recently-updated users, oldest-first up to `limit`.",
    )


def _require_admin(request: Request) -> None:
    """Allow admin_api_key OR a Google session JWT with `is_admin=true`.

    Same gate AdminServerStatus uses — keep the two consistent so an
    operator can switch between break-glass and session auth without
    surprises. Anything else 403s.
    """
    auth_type = getattr(request.state, "auth_type", "none")
    session_user = getattr(request.state, "session_user", None) or {}
    is_admin = (
        auth_type == "admin_api_key"
        or (auth_type == "google_session" and bool(session_user.get("is_admin")))
    )
    if not is_admin:
        raise HTTPException(status_code=403, detail="Admin-only endpoint.")


@router.get(
    "/state/admin/users",
    response_model=AdminUsersResponse,
    summary="List user_state rows (admin-only)",
)
def list_user_state(
    request: Request,
    _auth=Depends(verify_auth),
    db: Session = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=500),
):
    _require_admin(request)
    total = db.scalar(select(func.count()).select_from(UserState)) or 0
    rows = (
        db.execute(
            select(UserState)
            .order_by(UserState.updated_at.desc().nullslast())
            .limit(limit)
        )
        .scalars()
        .all()
    )
    recent = [
        AdminUserSummary(
            email=r.email,
            updated_at=r.updated_at,
            # Best-effort projection of the opaque blob — both fields are
            # well-known SPA shapes that have been stable since v1. If a
            # future SPA renames them, the values fall back to 0 instead
            # of throwing.
            xp=int((r.blob or {}).get("xp") or 0),
            streak=int((r.blob or {}).get("streak") or 0),
        )
        for r in rows
    ]
    return AdminUsersResponse(count=int(total), recent=recent)
