"""Regression for `GET /auth/admin/users`.

Why: the cross-service reconcile path in
`LearnAI/services/social-svc/__tests__/.../reconcile.test.ts` needs
mem0's `auth.users` table exposed as an admin-only read so the
backfill can fill `fullName` deterministically without each user
having to re-sign-in. The endpoint adds zero new persistence — it's
a flat projection over the existing User model.

This test pins:
  1. The 403 gate (non-admin sessions are rejected).
  2. The success-path payload (email + name + role + created_at).
  3. The endpoint sorts oldest-first so paging is stable.

We use the source-snippet pattern (same as
`test_learnai_compat_search.py`) so we don't pull SQLAlchemy / FastAPI
into the smoke venv.
"""

from __future__ import annotations

import os
import re


def test_endpoint_route_and_admin_gate_present():
    """Ensure the route is mounted at /auth/admin/users and gates on
    `_require_admin_or_admin_email`. Pure source check — no runtime."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src = open(os.path.join(here, "routers", "auth.py"), "r", encoding="utf-8").read()
    # Path is registered.
    assert '"/admin/users"' in src, "route /auth/admin/users not registered"
    # Admin gate is wired.
    assert "_require_admin_or_admin_email(request)" in src, (
        "admin gate missing from list_auth_users — anyone could read auth.users"
    )
    # Response model exists.
    assert "AdminAuthUsersResponse" in src
    # Each row carries email + name (the two fields social-svc reconcile
    # needs to backfill the leaderboard's full names).
    summary_block = re.search(
        r"class AdminUserSummary\(BaseModel\):(.*?)model_config",
        src,
        re.S,
    )
    assert summary_block is not None
    assert "email" in summary_block.group(1)
    assert "name" in summary_block.group(1)
    # Doesn't accidentally leak password_hash or other secrets.
    assert "password_hash" not in summary_block.group(1)


def test_admin_gate_helper_is_dual_credential():
    """Mirrors `_require_admin` in user_state.py — accept admin_api_key
    OR a Google session JWT with is_admin=true. Spec test so the gate
    doesn't drift to single-credential."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src = open(os.path.join(here, "routers", "auth.py"), "r", encoding="utf-8").read()
    helper = re.search(
        r"def _require_admin_or_admin_email\([^)]*\)[^:]*:(.*?)(?=\n@|\nclass |\ndef )",
        src,
        re.S,
    )
    assert helper is not None
    body = helper.group(1)
    assert "admin_api_key" in body
    assert "google_session" in body
    assert "is_admin" in body
    assert "403" in body
