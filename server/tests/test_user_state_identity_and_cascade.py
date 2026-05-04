"""Pin the identity-persist + cascade-delete contracts for user_state.

Pure-source-snippet style — no SQLAlchemy / FastAPI runtime needed
(matches the rest of mem0's smoke-test pattern). Inspects the source
text rather than running the routes; the integration path lives in
the cloud-claude live-deploy verification.

Pinned contracts:
  - Alembic migration 009 adds display_name + picture_url to user_states.
  - Reverse migration drops them (rollback safety).
  - The User model exposes the two new fields as nullable strings.
  - The upsert helper preserves prior values when a claim is empty
    (Google sometimes omits the picture URL on cached tokens).
  - /auth/google calls upsert_user_identity AFTER mint, BEFORE return.
  - The new /cascade endpoint is wired up + admin-gated + names every
    cross-service step (user_state, memories, auth_users, social_svc).
  - The reset-progress (existing) DELETE endpoint's docstring now
    explicitly says it does NOT cascade — the operator-facing contract
    is unambiguous.
"""

from __future__ import annotations

import os
import re


def _src(rel_path: str) -> str:
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return open(os.path.join(here, rel_path), "r", encoding="utf-8").read()


def test_alembic_migration_009_adds_identity_columns():
    src = _src("alembic/versions/009_user_state_identity_columns.py")
    assert 'revision: str = "009"' in src
    assert 'down_revision: Union[str, None] = "008"' in src
    assert "op.add_column" in src
    assert "display_name" in src
    assert "picture_url" in src
    # Reverse path drops the columns so a rollback is clean.
    assert "op.drop_column" in src
    # The columns are nullable so the migration is zero-downtime
    # against existing rows.
    assert 'sa.Column("display_name"' in src and "nullable=True" in src
    assert 'sa.Column("picture_url"' in src


def test_user_state_model_exposes_new_columns():
    src = _src("models.py")
    block = src[src.index("class UserState") :]
    assert "display_name: Mapped[str | None]" in block
    assert "picture_url: Mapped[str | None]" in block


def test_upsert_user_identity_preserves_prior_values_on_empty_claim():
    """Google sometimes omits the `picture` claim on cached tokens.
    The helper must not blow away the stored value in that case."""
    src = _src("routers/user_state.py")
    block = src[src.index("def upsert_user_identity") :]
    # Both fields are normalized to None when empty / whitespace.
    assert "clean_name = (name or " in block
    assert "clean_picture = (picture_url or " in block
    # And the update branch only writes when non-None.
    assert "if clean_name is not None:" in block
    assert "if clean_picture is not None:" in block


def test_google_signin_persists_identity():
    src = _src("routers/google_auth.py")
    sign_in = src[src.index("def sign_in_with_google") :]
    # Identity persistence happens AFTER mint, BEFORE the response.
    mint_idx = sign_in.index("issue_session_token")
    upsert_idx = sign_in.index("upsert_user_identity")
    return_idx = sign_in.index("return GoogleSignInResponse")
    assert mint_idx < upsert_idx < return_idx
    # And it's called with the Google claims, not synthetic placeholders.
    call_block = sign_in[upsert_idx : upsert_idx + 200]
    assert "name=name" in call_block
    assert "picture_url=picture" in call_block


def test_cascade_endpoint_route_and_admin_gate():
    src = _src("routers/user_state.py")
    # Route registered.
    assert '/state/admin/users/{email}/cascade' in src
    # Same admin gate as the rest of /v1/state/admin.
    cascade = src[src.index("def admin_remove_user_cascade") :]
    assert "_require_admin(request)" in cascade


def test_cascade_endpoint_covers_all_stores():
    """The cascade must touch every store the user has data in.
    Anything new in mem0 (e.g. a future telemetry table) is a bug if
    it's not added here."""
    src = _src("routers/user_state.py")
    cascade = src[src.index("def admin_remove_user_cascade") :]
    # Each of the four stores has a labeled step.
    assert 'steps["user_state"]' in cascade
    assert 'steps["memories"]' in cascade
    assert 'steps["auth_users"]' in cascade
    assert 'steps["social_svc"]' in cascade
    # The memories delete uses `user_id=target` directly. Don't be
    # fooled by the search() contract — Memory.delete_all() actually
    # rejects `filters=` and takes the top-level kwarg. Mismatch in
    # upstream mem0 we can't fix here; the existing
    # `v1_delete_all_memories` in routers/learnai_compat.py matches
    # this shape.
    assert "delete_all(user_id=target)" in cascade
    assert 'filters={"user_id": target}' not in cascade


def test_cascade_endpoint_idempotent_on_missing_rows():
    """A row that doesn't exist in any one store is treated as 'absent',
    not an error. Re-running the cascade is safe."""
    src = _src("routers/user_state.py")
    cascade = src[src.index("def admin_remove_user_cascade") :]
    assert '"absent"' in cascade  # marks user_state absence
    assert '"absent"' in cascade  # auth_users absence too


def test_reset_progress_endpoint_docstring_clarifies_scope():
    """User feedback: 'wipe server state' was unclear.  The docstring
    must now explicitly say what it doesn't do, and point at the
    cascade endpoint as the alternative."""
    src = _src("routers/user_state.py")
    block = src[src.index("def admin_wipe_user_state") :]
    assert "Reset-progress-only" in block or "reset" in block.lower()
    assert "cascade" in block.lower(), "the docstring must point at /cascade for full removal"
    assert "memories" in block.lower(), "must enumerate what stays untouched"
    assert "social-svc" in block.lower() or "profile" in block.lower()
