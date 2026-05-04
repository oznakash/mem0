"""Regression: /auth/google fans out to social-svc on signin.

Pre-fix, mem0 minted a session JWT and returned. social-svc only
heard about the user when the SPA happened to call /v1/social/me,
which created a window where a user could be cognition-side (mem0)
but socially invisible (no profile, no leaderboard row, no /u/handle
page). The LearnAI cross-service entity-wiring audit hit this with
6 stranded users.

Fix: an opt-in `SOCIAL_SVC_URL` env var. When set, /auth/google fires
a fire-and-forget POST to `/v1/social/admin/profiles/upsert` carrying
the Google identity (email + name + picture) so social-svc's profile
exists immediately, with full name, no SPA round-trip required.

This test pins:
  1. The fan-out helper exists and is wired into /auth/google.
  2. Same-host setups (SOCIAL_SVC_URL unset) silently skip.
  3. The fan-out runs on a daemon thread (never blocks the response).
  4. The admin token it mints carries `is_admin=true` (so social-svc's
     admin gate accepts it).

Source-snippet pattern (no SQLAlchemy / FastAPI runtime needed).
"""

from __future__ import annotations

import os


def _src() -> str:
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return open(os.path.join(here, "routers", "google_auth.py"), "r", encoding="utf-8").read()


def test_fanout_helper_is_defined_and_called_from_google_signin():
    src = _src()
    # Helper exists.
    assert "_ping_social_svc_async" in src, "fanout helper missing"
    # And it's called from sign_in_with_google AFTER issue_session_token
    # so the response shape doesn't depend on the fanout result.
    sign_in_block_start = src.index("def sign_in_with_google")
    response_block = src.index("return GoogleSignInResponse", sign_in_block_start)
    fanout_call = src.index("_ping_social_svc_async(", sign_in_block_start)
    assert sign_in_block_start < fanout_call < response_block, (
        "fanout must run between issue_session_token and the response"
    )


def test_fanout_skipped_when_social_svc_url_unset():
    src = _src()
    # The early-return guard is the contract that same-host setups
    # don't try to reach a non-existent neighbor service.
    assert 'if not SOCIAL_SVC_URL:' in src
    assert "return  # same-host setup; skip." in src


def test_fanout_runs_on_a_daemon_thread():
    """The fan-out must NEVER block the signin response. Daemon thread
    so it doesn't keep the process alive past shutdown either."""
    src = _src()
    assert "threading.Thread" in src
    assert "daemon=True" in src
    assert ".start()" in src


def test_fanout_mints_an_admin_token_using_shared_jwt_secret():
    """social-svc's admin gate accepts a Google session JWT with
    `is_admin=true`. The fan-out must mint that exact shape using
    JWT_SECRET (the secret both services share). Uses python-jose
    (matching `auth.py` — adding PyJWT would be a new dependency)."""
    src = _src()
    assert "_mint_admin_session_for_social" in src
    block = src[src.index("def _mint_admin_session_for_social") :]
    assert '"is_admin": True' in block
    assert "JWT_ALGORITHM" in block
    assert '"type": "session"' in block
    # Mints with jose (already a project dep), not PyJWT.
    assert "jose_jwt.encode" in block


def test_fanout_payload_includes_google_identity():
    """email is required; name + picture are passed when present so
    social-svc's upsert can populate displayName + pictureUrl."""
    src = _src()
    block = src[src.index("def _ping_social_svc_async") :]
    assert 'payload = {"email": email}' in block or 'payload["email"]' in block
    assert "fullName" in block
    assert "pictureUrl" in block


def test_failure_is_logged_not_raised():
    """A slow/dead social-svc must never break Google signin. The fan-out
    swallows exceptions and logs at WARNING."""
    src = _src()
    block = src[src.index("def _ping_social_svc_async") :]
    assert "except Exception" in block
    assert "_social_log.warning" in block
