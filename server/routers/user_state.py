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
    # Persisted Google identity (NULL when the user signed up via password
    # — auth.users carries the `name` for those). Updated on every
    # /auth/google signin; consumed by the social-svc reconcile path.
    display_name: Optional[str] = Field(
        None,
        description="Latest Google `name` claim seen on signin. NULL for password users.",
    )
    picture_url: Optional[str] = Field(
        None,
        description="Latest Google `picture` claim seen on signin. NULL for password users.",
    )
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
    # Email policy state (written by /v1/email/admin/* endpoints — opaque
    # blob, no schema migration). Surfaced here so the LearnAI Admin can
    # render queue badges + decide rate-limit / pause / unsub in one
    # round-trip.
    email_unsubscribed_at: Optional[int] = Field(
        None,
        description="Epoch ms; when set, all sends to this user are blocked.",
    )
    email_pause_until: Optional[int] = Field(
        None,
        description="Epoch ms; sends are paused until this time. Set automatically when N consecutive emails go unread.",
    )
    email_log: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Last few prepared sends. Each entry: {id, tpl, sent_at, opened_at, is_transactional}.",
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
    # Email policy fields are written by /v1/email/admin/* endpoints
    # into the same opaque blob. Surface the most recent few entries —
    # the LearnAI flushQueue uses the last 2 to decide whether to pause.
    email_log_raw = blob.get("emailLog") if isinstance(blob.get("emailLog"), list) else []
    email_log = [e for e in email_log_raw if isinstance(e, dict)][:5]
    return AdminUserSummary(
        email=row.email,
        display_name=row.display_name,
        picture_url=row.picture_url,
        created_at=row.created_at,
        updated_at=row.updated_at,
        signup_at=signup_at,
        last_seen_at=last_seen_at,
        xp=_safe_int(blob.get("xp")),
        streak=_safe_int(blob.get("streak")),
        total_sparks=total_sparks,
        total_minutes=total_minutes,
        activity_14d=activity,
        email_unsubscribed_at=blob.get("emailUnsubscribedAt") if isinstance(blob.get("emailUnsubscribedAt"), int) else None,
        email_pause_until=blob.get("emailPauseUntil") if isinstance(blob.get("emailPauseUntil"), int) else None,
        email_log=email_log,
    )


# -- Identity persistence on signin -----------------------------------------
#
# Called by /auth/google after the session token is minted. Upserts the
# user's display_name and picture_url onto user_state so social-svc's
# reconcile path can backfill those fields onto profiles. Idempotent:
# if the row already exists, only the two identity columns are touched
# (the blob is left alone). If the row doesn't exist, a stub is created
# with empty blob and the two identity columns set.
#
# Failures are swallowed — the signin flow must never fail because of a
# write to a side table. Logs at WARN.

import logging
_identity_log = logging.getLogger("user_state.identity")


def upsert_user_identity(
    db: Session,
    *,
    email: str,
    name: Optional[str],
    picture_url: Optional[str],
) -> None:
    """Best-effort write of the user's Google name + avatar to user_state.
    Never raises into the caller (which is the signin path). When `name`
    or `picture_url` is None / empty / whitespace-only, that column is
    left untouched — preserves whatever the previous signin stored."""
    try:
        normalized_email = (email or "").strip().lower()
        if not normalized_email:
            return
        clean_name = (name or "").strip() or None
        clean_picture = (picture_url or "").strip() or None
        row = db.scalar(select(UserState).where(UserState.email == normalized_email))
        if row is None:
            db.add(
                UserState(
                    email=normalized_email,
                    blob={},
                    display_name=clean_name,
                    picture_url=clean_picture,
                )
            )
        else:
            # Only overwrite when the new claim is non-empty. A user who
            # later signs in with a missing claim shouldn't blow away the
            # stored value — Google sometimes omits the picture URL on
            # cached tokens.
            if clean_name is not None:
                row.display_name = clean_name
            if clean_picture is not None:
                row.picture_url = clean_picture
        db.commit()
    except Exception as exc:
        _identity_log.warning(
            "upsert_user_identity_failed",
            extra={"email_hash": (email or "")[:3], "err": str(exc)},
        )
        db.rollback()


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
    summary="Reset a user's progress only (admin-only) — wipes user_state",
)
def admin_wipe_user_state(
    email: str,
    request: Request,
    _auth=Depends(verify_auth),
    db: Session = Depends(get_db),
):
    """**Reset-progress-only** action. Removes the `user_state` row for
    `email` so the SPA's PlayerState (xp, streak, history, calibration)
    starts over on the user's next sign-in. Does NOT touch:

      - memories (mem0 vector store) — use `/v1/state/admin/users/{email}/cascade`
        for a full wipe.
      - the user's social-svc profile, follow graph, or stream events.
      - the user's signed-in session (the JWT is stateless).

    Idempotent. Returns 200 + a clear message either way."""
    _require_admin(request)
    target = (email or "").lower().strip()
    if not target:
        raise HTTPException(status_code=400, detail="Email path param is empty.")
    row = db.scalar(select(UserState).where(UserState.email == target))
    if row is None:
        return MessageResponse(message=f"No user_state row for {target}; nothing to wipe.")
    db.delete(row)
    db.commit()
    return MessageResponse(
        message=f"Reset progress for {target} (user_state row removed). The user's memories, profile, and social graph are intact — use the `cascade` endpoint to fully remove the user."
    )


@router.delete(
    "/state/admin/users/{email}/cascade",
    response_model=MessageResponse,
    summary="Remove a user permanently (admin-only) — cascades across mem0 + social-svc",
)
def admin_remove_user_cascade(
    email: str,
    request: Request,
    _auth=Depends(verify_auth),
    db: Session = Depends(get_db),
):
    """**Permanent-removal** action. Wipes EVERY trace of the user
    across mem0 + social-svc so the user's next sign-in starts a brand-
    new onboarding flow:

      1. mem0 user_state row (xp, streak, history, calibration).
      2. mem0 memories — every entry where user_id = email.
      3. mem0 auth.users row (only present for password-registered users).
      4. social-svc profile — fanned out via SOCIAL_SVC_URL admin DELETE.
         Cascades inside social-svc to follows, blocks, reports, events.

    Idempotent: a row that doesn't exist is a no-op for that step.

    The fan-out to social-svc is done synchronously here (not fire-and-
    forget) so the operator's response reflects the true cross-service
    state. Failures don't roll back what was already deleted — the
    response carries a structured `steps` map so the operator sees
    exactly which deletes succeeded.

    Same admin gate as the rest of /v1/state/admin. After this call,
    a new sign-in by the same email will trigger a fresh onboarding."""
    _require_admin(request)
    target = (email or "").lower().strip()
    if not target or "@" not in target:
        raise HTTPException(status_code=400, detail="Invalid email path param.")

    steps: dict[str, Any] = {}

    # Step 1 — user_state row.
    try:
        row = db.scalar(select(UserState).where(UserState.email == target))
        if row is None:
            steps["user_state"] = "absent"
        else:
            db.delete(row)
            db.commit()
            steps["user_state"] = "deleted"
    except Exception as exc:
        db.rollback()
        steps["user_state"] = f"error: {exc}"

    # Step 2 — memories (vector store + history).
    try:
        from server_state import get_memory_instance

        get_memory_instance().delete_all(filters={"user_id": target})
        steps["memories"] = "deleted"
    except Exception as exc:
        steps["memories"] = f"error: {exc}"

    # Step 3 — auth.users row (only for password users).
    try:
        from models import User

        user_row = db.scalar(select(User).where(User.email == target))
        if user_row is None:
            steps["auth_users"] = "absent"
        else:
            db.delete(user_row)
            db.commit()
            steps["auth_users"] = "deleted"
    except Exception as exc:
        db.rollback()
        steps["auth_users"] = f"error: {exc}"

    # Step 4 — social-svc fanout. Reuses the existing
    # `_ping_social_svc_async` style (admin token + cross-host POST),
    # but synchronous here so the response reflects the cross-service
    # state. Skipped when SOCIAL_SVC_URL is unset (same-host setups
    # share the volume — operator runs the social-svc DELETE separately).
    try:
        from routers.google_auth import (
            SOCIAL_SVC_URL,
            _mint_admin_session_for_social,
        )
        import json
        import urllib.error
        import urllib.request

        if not SOCIAL_SVC_URL:
            steps["social_svc"] = "skipped (SOCIAL_SVC_URL unset)"
        else:
            tok = _mint_admin_session_for_social("auth-cascade@learnai")
            # social-svc deletes by handle; resolve via a quick lookup.
            # The admin upsert returns { handle, email } when re-called
            # but we need a lookup-only path. Read /v1/social/admin/profiles
            # to find the handle for our email.
            list_req = urllib.request.Request(
                f"{SOCIAL_SVC_URL}/v1/social/admin/profiles",
                headers={"Authorization": f"Bearer {tok}"},
                method="GET",
            )
            handle: Optional[str] = None
            try:
                with urllib.request.urlopen(list_req, timeout=4.0) as resp:
                    body = json.loads(resp.read().decode("utf-8"))
                for p in body.get("profiles", []):
                    if p.get("emailHash") and p.get("handle"):
                        # masked email — match by hash. The admin endpoint
                        # echoes oznakash's email verbatim (admin) and masks
                        # others — both flows resolve via `emailMasked`
                        # equality on the original email.
                        emasked = p.get("emailMasked", "") or ""
                        if emasked.lower() == target.lower():
                            handle = p["handle"]
                            break
                        # masked form: first 3 chars + ***@<domain>
                        if "***" in emasked:
                            local, _, domain = target.partition("@")
                            if emasked.startswith(local[:3]) and emasked.endswith(f"@{domain}"):
                                handle = p["handle"]
                                break
            except urllib.error.URLError as e:
                steps["social_svc"] = f"list_error: {e}"
                handle = None

            if not handle:
                steps["social_svc"] = "absent_or_unresolvable"
            else:
                del_req = urllib.request.Request(
                    f"{SOCIAL_SVC_URL}/v1/social/admin/profiles/by-handle/{handle}",
                    headers={"Authorization": f"Bearer {tok}"},
                    method="DELETE",
                )
                try:
                    with urllib.request.urlopen(del_req, timeout=4.0) as resp:
                        steps["social_svc"] = f"deleted (handle={handle}, status={resp.getcode()})"
                except urllib.error.HTTPError as he:
                    steps["social_svc"] = f"http_error: {he.code}"
    except Exception as exc:
        steps["social_svc"] = f"error: {exc}"

    return MessageResponse(
        message=(
            f"Cascade-removed {target}. Steps: {steps}. "
            f"On next sign-in, this email will start fresh onboarding."
        )
    )
