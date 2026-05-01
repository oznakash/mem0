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
    created_at: Optional[datetime] = Field(
        None,
        description="Row creation timestamp — proxy for first server-side sync.",
    )
    updated_at: Optional[datetime] = Field(
        None,
        description="Last server-side write to the blob.",
    )
    signup_at: Optional[int] = Field(
        None,
        description="`profile.createdAt` from the blob (epoch ms), if present.",
    )
    last_seen_at: Optional[int] = Field(
        None,
        description="Best-effort last-active hint, derived from blob fields.",
    )
    xp: int = 0
    streak: int = 0
    total_sparks: int = Field(0, description="Sum of `history[].sparkIds.length`.")
    total_minutes: int = Field(0, description="Sum of `history[].minutes`.")
    activity_14d: list[int] = Field(
        default_factory=list,
        description="Sparks per day for the last 14 days, oldest-first.",
    )


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


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return n if n >= 0 else default


def _activity_14d_from_history(history: Any, now_ms: int) -> tuple[list[int], int, int]:
    """Build a (14-day activity, total_sparks, total_minutes) tuple from
    the blob's `history` array. Mirrors the SPA's own `computeActivity14d`
    helper so admin charts stay consistent with what the player sees in
    their own dashboard. Skips malformed entries silently — the blob is
    opaque to the server and has no schema guarantees."""
    days: list[int] = [0] * 14
    total_sparks = 0
    total_minutes = 0
    if not isinstance(history, list):
        return days, total_sparks, total_minutes
    day_ms = 24 * 60 * 60 * 1000
    today_start_ms = now_ms - (now_ms % day_ms)
    for session in history:
        if not isinstance(session, dict):
            continue
        spark_ids = session.get("sparkIds")
        n_sparks = len(spark_ids) if isinstance(spark_ids, list) else 0
        total_sparks += n_sparks
        total_minutes += _safe_int(session.get("minutes"))
        ts = session.get("ts")
        if not isinstance(ts, (int, float)):
            continue
        offset = round((today_start_ms - (int(ts) - (int(ts) % day_ms))) / day_ms)
        if 0 <= offset < 14:
            # index 0 = oldest (13 days ago), 13 = today
            days[13 - offset] += n_sparks
    return days, total_sparks, total_minutes


def _derive_summary(row: UserState, now_ms: int) -> AdminUserSummary:
    """Build the admin-shape summary from a UserState row. The blob is
    opaque, so every field has a fallback; missing keys never raise."""
    blob = row.blob or {}
    profile = blob.get("profile") if isinstance(blob.get("profile"), dict) else {}
    activity, total_sparks, total_minutes = _activity_14d_from_history(
        blob.get("history"), now_ms
    )
    signup_at_raw = profile.get("createdAt") if profile else None
    signup_at = int(signup_at_raw) if isinstance(signup_at_raw, (int, float)) else None
    streak_updated = blob.get("streakUpdatedAt")
    last_seen_at = (
        int(streak_updated)
        if isinstance(streak_updated, (int, float)) and streak_updated > 0
        else (
            int(row.updated_at.timestamp() * 1000)
            if row.updated_at is not None
            else None
        )
    )
    return AdminUserSummary(
        email=row.email,
        created_at=row.created_at,
        updated_at=row.updated_at,
        signup_at=signup_at,
        last_seen_at=last_seen_at,
        xp=_safe_int(blob.get("xp")),
        streak=_safe_int(blob.get("streak")),
        total_sparks=total_sparks,
        total_minutes=total_minutes,
        activity_14d=activity,
    )


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
    now_ms = int(datetime.now().timestamp() * 1000)
    return AdminUsersResponse(
        count=int(total),
        recent=[_derive_summary(r, now_ms) for r in rows],
    )


@router.delete(
    "/state/admin/users/{email}",
    response_model=MessageResponse,
    summary="Wipe a specific user's user_state (admin-only)",
)
def admin_wipe_user_state(
    email: str,
    request: Request,
    _auth=Depends(verify_auth),
    db: Session = Depends(get_db),
):
    """Destructive: removes the user_state row for `email`. The user can
    sign in again afterwards and gets a fresh slate. Used by the LearnAI
    Admin "Reset progress" action on real users — the SPA-level local
    `resetUserProgress` only mutates UI state and would silently rebound
    on the next mem0 fetch, which surfaced as a footgun.

    Same admin gate as `/state/admin/users`. The path-encoded `email` is
    the recipient — no body, no JWT-binding to the caller. Returns 200
    with `wiped: false` when the row didn't exist (idempotent), 200 with
    `wiped: true` when it did."""
    _require_admin(request)
    target = (email or "").lower().strip()
    if not target:
        raise HTTPException(status_code=400, detail="Email path param is empty.")
    row = db.scalar(select(UserState).where(UserState.email == target))
    if row is None:
        return MessageResponse(message=f"No user_state row for {target}; nothing to wipe.")
    db.delete(row)
    db.commit()
    return MessageResponse(message=f"Wiped user_state for {target}.")
