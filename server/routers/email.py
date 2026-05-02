"""Email policy endpoints — token-minting, unsubscribe, open tracking.

Three small endpoints that let the LearnAI Admin Console enforce a
per-recipient rate limit (one email per 24h) without having to share
the JWT_SECRET with the SPA bundle:

  * POST /v1/email/admin/prepare        (admin)  — mints unsubscribe
    + open-pixel URLs, records a `prepared` log entry, returns the
    recipient's current policy state so the SPA can decide
    "send" / "skip-rate-limit" / "skip-unsubscribed" / "skip-paused".

  * POST /v1/email/unsubscribe?token=…  (public, HMAC) — sets
    `emailUnsubscribedAt` on the user_state blob.

  * GET  /v1/email/track/open?token=…   (public, HMAC) — records an
    `openedAt` against a previously-prepared log entry, returns a
    1×1 transparent PNG.

State lives in the opaque user_state blob (no schema migration):

    user_state.blob.emailLog          : list[{id, tpl, ts, opened_at?}] (last 5)
    user_state.blob.emailUnsubscribedAt: int | None  (epoch ms)
    user_state.blob.emailPauseUntil    : int | None  (epoch ms)

Tokens are HMAC-signed with the same JWT_SECRET we already use for
session JWTs. They carry `{email, kind, log_id?, exp}` and live for 90
days — long enough to outlive the email's actual lifetime in any
reasonable inbox.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response, JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from auth import JWT_SECRET, verify_auth
from db import get_db
from models import UserState


router = APIRouter(prefix="/v1/email", tags=["email"])

# 90 days. Email clients can forward, archive, leave threads open
# indefinitely. Don't make tokens evaporate too fast.
TOKEN_TTL_SECONDS = 90 * 24 * 60 * 60

# 1×1 transparent PNG (67 bytes), inlined so we never have to ship a
# binary asset. Base64 → bytes at import time.
_TRACK_PIXEL = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7w"
    "AAAABJRU5ErkJggg=="
)

# Trim emailLog to this many entries — enough for the LearnAI policy
# checks (which read the last 2-5) without unbounded growth.
EMAIL_LOG_MAX = 10


def _require_admin(request: Request) -> None:
    auth_type = getattr(request.state, "auth_type", "none")
    session_user = getattr(request.state, "session_user", None) or {}
    is_admin = (
        auth_type == "admin_api_key"
        or (auth_type == "google_session" and bool(session_user.get("is_admin")))
    )
    if not is_admin:
        raise HTTPException(status_code=403, detail="Admin-only endpoint.")


# ----------------------- token signing -----------------------------------

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _sign_token(payload: dict[str, Any]) -> str:
    if not JWT_SECRET:
        raise HTTPException(status_code=500, detail="JWT_SECRET not configured.")
    body = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(JWT_SECRET.encode(), body.encode(), hashlib.sha256).digest()
    return f"{body}.{_b64url_encode(sig)}"


def _verify_token(token: str, expected_kind: str) -> dict[str, Any]:
    if not JWT_SECRET:
        raise HTTPException(status_code=500, detail="JWT_SECRET not configured.")
    try:
        body, sig = token.split(".", 1)
        expected = hmac.new(JWT_SECRET.encode(), body.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(_b64url_decode(sig), expected):
            raise ValueError("bad signature")
        payload = json.loads(_b64url_decode(body))
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token.")
    if payload.get("kind") != expected_kind:
        raise HTTPException(status_code=401, detail="Token is for a different action.")
    if payload.get("exp", 0) < int(time.time()):
        raise HTTPException(status_code=401, detail="Token has expired.")
    if not payload.get("email"):
        raise HTTPException(status_code=401, detail="Token is missing email.")
    return payload


# ----------------------- /admin/prepare ---------------------------------

class PrepareRequest(BaseModel):
    to: str = Field(..., description="Recipient email.")
    template_id: str = Field(..., description="Template id, e.g. 'welcome' or 'first-spark'.")
    # Mark transactional vs marketing on the SPA side and pass through;
    # the server just stores it on the log entry for later analysis.
    is_transactional: bool = Field(False, description="Set true for celebration / event-driven sends.")


class RecentEmailEntry(BaseModel):
    id: str
    tpl: str
    sent_at: Optional[int] = None
    opened_at: Optional[int] = None
    is_transactional: bool = False


class PrepareResponse(BaseModel):
    decision: str = Field(..., description="'send' | 'skip-unsubscribed' | 'skip-paused' | 'skip-rate-limit'")
    log_id: Optional[str] = None
    unsubscribe_url: Optional[str] = None
    open_pixel_url: Optional[str] = None
    # Surfacing user policy state so the SPA can render queue badges
    # like 'rate-limited until 8pm' without a second round-trip.
    user: dict[str, Any]


def _ensure_blob(row: UserState) -> dict[str, Any]:
    """user_state row may exist (from /v1/state writes) or not yet (the
    SPA has never called /v1/state for this user). Either way we want
    the email-policy fields available. Return a mutable dict reference
    that's safe to assign back to row.blob."""
    blob = dict(row.blob or {})
    if "emailLog" not in blob or not isinstance(blob["emailLog"], list):
        blob["emailLog"] = []
    return blob


def _get_or_create_state(db: Session, email: str) -> UserState:
    row = db.scalar(select(UserState).where(UserState.email == email))
    if row is not None:
        return row
    row = UserState(email=email, blob={})
    db.add(row)
    db.flush()
    return row


@router.post(
    "/admin/prepare",
    response_model=PrepareResponse,
    summary="Mint unsubscribe + open-tracking URLs and record a prepared log entry.",
)
def prepare_send(
    body: PrepareRequest,
    request: Request,
    _auth=Depends(verify_auth),
    db: Session = Depends(get_db),
):
    _require_admin(request)
    email = (body.to or "").strip().lower()
    if not email:
        raise HTTPException(status_code=400, detail="`to` is required.")

    # request.base_url respects whatever scheme the inbound request came
    # in on. Behind Traefik that's plain http between proxy and app —
    # but emails sent to real recipients must use https. Honor
    # X-Forwarded-Proto, and let an operator pin a canonical base via
    # PUBLIC_BASE_URL when the deployment is exotic. Last-resort: silently
    # upgrade non-localhost http to https since cloud-claude is always
    # TLS-fronted.
    pinned = os.environ.get("PUBLIC_BASE_URL", "").strip().rstrip("/")
    if pinned:
        base_url = pinned
    else:
        proto = (request.headers.get("x-forwarded-proto") or "").strip().lower()
        raw = str(request.base_url).rstrip("/")
        if proto == "https" and raw.startswith("http://"):
            raw = "https://" + raw[len("http://"):]
        elif raw.startswith("http://") and "localhost" not in raw and "127.0.0.1" not in raw:
            raw = "https://" + raw[len("http://"):]
        base_url = raw
    row = _get_or_create_state(db, email)
    blob = _ensure_blob(row)
    now_ms = int(time.time() * 1000)

    unsubscribed_at = blob.get("emailUnsubscribedAt")
    pause_until = blob.get("emailPauseUntil")
    log = blob.get("emailLog") or []

    # Most-recent entries first, capped to last 5 for the policy decision
    # and surfaced shape on the response.
    recent_for_policy = sorted(
        log,
        key=lambda e: int(e.get("sent_at") or 0),
        reverse=True,
    )[:5]

    user_state_view = {
        "email_unsubscribed_at": unsubscribed_at,
        "email_pause_until": pause_until,
        "recent_emails": recent_for_policy,
    }

    # Hard skips before doing anything else.
    if unsubscribed_at:
        return PrepareResponse(decision="skip-unsubscribed", user=user_state_view)
    if isinstance(pause_until, int) and pause_until > now_ms:
        return PrepareResponse(decision="skip-paused", user=user_state_view)

    # 24h cap: if the most-recent prepared log entry is < 24h old, skip.
    # Calling code (LearnAI) is also responsible for batching its own
    # in-flight queue; this is the server-side belt-and-braces.
    if recent_for_policy:
        last = recent_for_policy[0]
        last_ts = int(last.get("sent_at") or 0)
        if last_ts and (now_ms - last_ts) < 24 * 60 * 60 * 1000:
            return PrepareResponse(decision="skip-rate-limit", user=user_state_view)

    # Mint a new log entry + tokens.
    log_id = secrets.token_urlsafe(8)
    exp = int(time.time()) + TOKEN_TTL_SECONDS
    unsub_token = _sign_token({"email": email, "kind": "unsub", "exp": exp})
    open_token = _sign_token(
        {"email": email, "kind": "open", "log_id": log_id, "exp": exp}
    )

    new_entry = {
        "id": log_id,
        "tpl": body.template_id,
        "sent_at": now_ms,  # optimistic — SPA confirms via /admin/sent if it wants to
        "opened_at": None,
        "is_transactional": bool(body.is_transactional),
    }

    blob["emailLog"] = ([new_entry] + log)[:EMAIL_LOG_MAX]
    row.blob = blob
    db.commit()

    return PrepareResponse(
        decision="send",
        log_id=log_id,
        unsubscribe_url=f"{base_url}/v1/email/unsubscribe?token={unsub_token}",
        open_pixel_url=f"{base_url}/v1/email/track/open?token={open_token}",
        user={
            "email_unsubscribed_at": unsubscribed_at,
            "email_pause_until": pause_until,
            "recent_emails": [new_entry] + recent_for_policy,
        },
    )


# ----------------------- /unsubscribe ---------------------------------

class UnsubscribeResponse(BaseModel):
    ok: bool
    email: str
    unsubscribed_at: int


@router.post(
    "/unsubscribe",
    response_model=UnsubscribeResponse,
    summary="One-click unsubscribe via signed token. No auth required (HMAC validates).",
)
def unsubscribe(token: str, db: Session = Depends(get_db)):
    payload = _verify_token(token, "unsub")
    email = (payload.get("email") or "").lower()
    row = _get_or_create_state(db, email)
    blob = _ensure_blob(row)
    ts = int(time.time() * 1000)
    blob["emailUnsubscribedAt"] = ts
    # Clear any pending pause — unsub supersedes everything.
    blob["emailPauseUntil"] = None
    row.blob = blob
    db.commit()
    return UnsubscribeResponse(ok=True, email=email, unsubscribed_at=ts)


@router.get(
    "/unsubscribe",
    response_model=UnsubscribeResponse,
    summary="Same as POST — provided so a direct email-client click also works.",
)
def unsubscribe_get(token: str, db: Session = Depends(get_db)):
    return unsubscribe(token, db)


# ----------------------- /track/open ----------------------------------

@router.get(
    "/track/open",
    response_class=Response,
    summary="1×1 PNG that records an email-open against the prepared log entry.",
)
def track_open(token: str, db: Session = Depends(get_db)):
    payload = _verify_token(token, "open")
    email = (payload.get("email") or "").lower()
    log_id = payload.get("log_id") or ""
    if email and log_id:
        row = db.scalar(select(UserState).where(UserState.email == email))
        if row is not None:
            blob = dict(row.blob or {})
            log = list(blob.get("emailLog") or [])
            ts = int(time.time() * 1000)
            mutated = False
            for entry in log:
                if entry.get("id") == log_id and not entry.get("opened_at"):
                    entry["opened_at"] = ts
                    mutated = True
                    break
            if mutated:
                blob["emailLog"] = log
                row.blob = blob
                db.commit()
    # Always return the pixel so a flaky token doesn't break the email
    # client's render. Cache-Control: no-store so retries actually re-hit.
    return Response(
        content=_TRACK_PIXEL,
        media_type="image/png",
        headers={"Cache-Control": "no-store, max-age=0"},
    )
