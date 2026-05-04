"""Add display_name + picture_url to user_states for Google identity persistence

Revision ID: 009
Revises: 008
Create Date: 2026-05-04

Pre-fix, the user's Google name + avatar URL lived only in the session
JWT. Once the session expired, mem0 had no record of either — so when
a downstream reconcile (`/v1/social/admin/reconcile-from-mem0`) tried
to fill `fullName` for a Google-signed-in user, it had no source data.

Two new nullable columns persist the latest Google identity claims on
every signin (handled in `routers/google_auth.py`). Reconcile now
joins these in. NULL-default keeps the migration zero-downtime —
existing rows are unaffected; pre-migration sessions still work.

Down-migration drops the columns. mem0 user_state's blob (PlayerState)
is unaffected by either direction.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "009"
down_revision: Union[str, None] = "008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "user_states",
        sa.Column("display_name", sa.String(255), nullable=True),
    )
    op.add_column(
        "user_states",
        sa.Column("picture_url", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("user_states", "picture_url")
    op.drop_column("user_states", "display_name")
