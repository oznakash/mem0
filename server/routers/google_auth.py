"""Production sign-in via Google ID token.

Browsers (e.g., the LearnAI SPA) get a Google ID token via Google Identity
Services, POST it here, and receive back a session JWT signed with
JWT_SECRET. Subsequent requests use that session JWT in the Authorization
header.

Sessions are stateless JWTs with a `type: "session"` claim and an N-day
expiry (configurable via SESSION_TTL_DAYS env var, defaults to 7).
Server-side signout is best-effort: stateless JWTs can't be revoked
individually without a denylist (out of scope for v1). Clients are expected
to discard the token. Token rotation happens by signing in again.

The Gmail-only restriction matches the SPA's existing policy. Admin status
is read from the ADMIN_EMAILS env var (comma-separated allowlist).
"""

import os
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from auth import (
    ADMIN_API_KEY,
    ADMIN_EMAILS,
    GOOGLE_OAUTH_CLIENT_ID,
    JWT_SECRET,
    SESSION_TTL_DAYS,
    is_admin_email,
    issue_session_token,
    verify_auth,
    verify_google_id_token,
)


router = APIRouter(prefix="/auth", tags=["auth"])


class PublicConfigResponse(BaseModel):
    """Public, unauth'd handshake values the SPA needs to bootstrap sign-in.

    Only operator-set public values are exposed here. No secrets, no
    user data, no admin-only fields. The point is: a fresh-localStorage
    visitor (new device, cleared cookies) can fetch this and self-heal,
    instead of having to paste a Client ID by hand.
    """
    google_client_id: str
    session_ttl_days: int


@router.get(
    "/config",
    response_model=PublicConfigResponse,
    summary="Public sign-in handshake — Google Client ID + session TTL",
)
def get_public_config():
    """Return the public OAuth + session config. Unauthenticated by design.

    Exposes:
      - GOOGLE_OAUTH_CLIENT_ID (already a public OAuth client ID)
      - SESSION_TTL_DAYS       (server-side default, used to mint sessions)

    The mem0 admin key, JWT_SECRET, OpenAI key, and database creds are
    never returned here. Adding fields requires a deliberate review.
    """
    return PublicConfigResponse(
        google_client_id=GOOGLE_OAUTH_CLIENT_ID,
        session_ttl_days=SESSION_TTL_DAYS,
    )


class GoogleSignInRequest(BaseModel):
    id_token: str = Field(..., description="Google ID token (JWT) returned by Google Identity Services.")


class SessionUser(BaseModel):
    email: str
    name: Optional[str] = None
    picture: Optional[str] = None


class GoogleSignInResponse(BaseModel):
    session: str
    user: SessionUser
    is_admin: bool
    expires_at: int


@router.post("/google", response_model=GoogleSignInResponse, summary="Sign in with a Google ID token")
def sign_in_with_google(req: GoogleSignInRequest):
    """Verify a Google-signed ID token, issue a session JWT.

    Restricted to @gmail.com addresses (matches the SPA's existing policy).
    Returns 401 if the Google token is invalid/expired/wrong-audience, 403
    if the email is non-Gmail, or 500 if the server isn't configured.
    """
    claims = verify_google_id_token(req.id_token)
    email = (claims.get("email") or "").lower()
    if not email:
        raise HTTPException(status_code=400, detail="Google ID token is missing the email claim.")
    if not email.endswith("@gmail.com"):
        raise HTTPException(
            status_code=403,
            detail="Only @gmail.com addresses are allowed to sign in.",
        )

    is_admin = is_admin_email(email)
    name = claims.get("name")
    picture = claims.get("picture")

    token, expires_at = issue_session_token(
        email=email, name=name, picture=picture, is_admin=is_admin
    )

    return GoogleSignInResponse(
        session=token,
        user=SessionUser(email=email, name=name, picture=picture),
        is_admin=is_admin,
        expires_at=int(expires_at.timestamp()),
    )


class SessionResponse(BaseModel):
    email: Optional[str] = None
    name: Optional[str] = None
    picture: Optional[str] = None
    is_admin: bool
    expires_at: Optional[int] = None
    auth_type: str


@router.get("/session", response_model=SessionResponse, summary="Get the current session user")
def get_session(request: Request, _auth=Depends(verify_auth)):
    """Return the current user, derived from whichever auth credential was presented.

    Used by the SPA on app load to validate that the stored session token is
    still good. Returns 401 if no valid credential was presented (verify_auth
    raises before we get here).

    Mounted at /auth/session (not /auth/me) to avoid colliding with the
    dashboard's existing /auth/me endpoint.
    """
    auth_type = getattr(request.state, "auth_type", "none")
    session_user = getattr(request.state, "session_user", None)

    if auth_type == "google_session" and session_user:
        return SessionResponse(
            email=session_user.get("email"),
            name=session_user.get("name"),
            picture=session_user.get("picture"),
            is_admin=bool(session_user.get("is_admin")),
            expires_at=session_user.get("exp"),
            auth_type="google_session",
        )

    if auth_type == "admin_api_key":
        return SessionResponse(is_admin=True, auth_type="admin_api_key")

    return SessionResponse(is_admin=False, auth_type=auth_type)


class AdminServerStatusResponse(BaseModel):
    """Operator-only view of which env-driven knobs are configured on the
    server. Only booleans + non-secret lists are exposed — never secret
    values. Renders in the LearnAI Admin → Memory tab as a sanity check.
    """
    google_oauth_client_id: str
    admin_emails: List[str]
    cors_origins: List[str]
    session_ttl_days: int
    history_db_path: str
    openai_api_key_set: bool
    jwt_secret_set: bool
    admin_api_key_set: bool


@router.get(
    "/admin/status",
    response_model=AdminServerStatusResponse,
    summary="Server config snapshot (admin-only)",
)
def get_admin_status(request: Request, _auth=Depends(verify_auth)):
    """Surface env-driven config state to authenticated admins.

    Authorisation:
      * google_session JWT with `is_admin: true` claim → allowed
      * admin_api_key bearer (operator break-glass)             → allowed
      * anything else                                            → 403

    Booleans only for secrets (OpenAI / JWT_SECRET / ADMIN_API_KEY) so
    operators can verify they're set without ever transmitting the values.
    """
    auth_type = getattr(request.state, "auth_type", "none")
    session_user = getattr(request.state, "session_user", None) or {}
    is_admin = (
        auth_type == "admin_api_key"
        or (auth_type == "google_session" and bool(session_user.get("is_admin")))
    )
    if not is_admin:
        raise HTTPException(status_code=403, detail="Admin-only endpoint.")

    cors_origins = [o.strip() for o in os.environ.get("CORS_ORIGINS", "").split(",") if o.strip()]
    return AdminServerStatusResponse(
        google_oauth_client_id=GOOGLE_OAUTH_CLIENT_ID,
        admin_emails=list(ADMIN_EMAILS),
        cors_origins=cors_origins,
        session_ttl_days=SESSION_TTL_DAYS,
        history_db_path=os.environ.get("HISTORY_DB_PATH", "/app/data/history.db"),
        openai_api_key_set=bool(os.environ.get("OPENAI_API_KEY")),
        jwt_secret_set=bool(JWT_SECRET),
        admin_api_key_set=bool(ADMIN_API_KEY),
    )


class SignOutResponse(BaseModel):
    message: str


@router.post("/google/signout", response_model=SignOutResponse, summary="Sign out (client-side)")
def sign_out(_auth=Depends(verify_auth)):
    """Sessions are stateless JWTs — server doesn't track them.

    Returning success here is just a UX hint to the client to discard its
    session token. Real revocation requires a denylist; out of scope for v1.
    Operators can rotate JWT_SECRET to invalidate every active session at
    once (nuclear option).
    """
    return SignOutResponse(message="Signed out. Discard the session token client-side.")
