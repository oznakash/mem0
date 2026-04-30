"""Create user_states table for cross-device PlayerState sync

Revision ID: 007
Revises: 006
Create Date: 2026-04-30

The LearnAI SPA stores its PlayerState (XP, streak, history, badges,
profile, prefs, etc.) in browser localStorage. That works on a single
device but breaks the moment the same user signs in on a phone or a
laptop. This table holds a single per-user JSON blob that the SPA
loads on sign-in and writes back (debounced) on every mutation.

Keyed on email — the same identifier mem0 already uses as `user_id`
in the memories table. One row per user. Unique email constraint
prevents two rows ever existing for the same identity.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "007"
down_revision: Union[str, None] = "006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "user_states",
        sa.Column("id", sa.UUID(), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("email", sa.String(255), nullable=False, unique=True, index=True),
        sa.Column("blob", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("user_states")
