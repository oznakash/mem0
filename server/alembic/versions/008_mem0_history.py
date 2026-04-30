"""Move mem0's SQLite history + messages stores into Postgres

Revision ID: 008
Revises: 007
Create Date: 2026-04-30

mem0 ships a SQLiteManager that writes its memory-edit audit trail and
its message buffer to a single SQLite file at HISTORY_DB_PATH. On
hosting platforms that don't expose persistent volumes (Cloud-Claude,
many others), that file lives on the container's ephemeral overlay
filesystem and dies on every rebuild.

The vector store (the actual memories) is already Postgres + pgvector,
so we have a persistent backing store right there. This migration adds
two tables — `mem0_history` and `mem0_messages` — with the same column
shape mem0's SQLiteManager uses, and a companion `PostgresHistoryManager`
class is wired into the running Memory instance at startup.

Schema mirrors mem0's CREATE TABLE in mem0/memory/storage.py exactly so
get_history() returns rows with identical fields. memory_id and
session_scope are indexed for the lookup paths actually exercised by the
Memory class.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "008"
down_revision: Union[str, None] = "007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "mem0_history",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("memory_id", sa.String(64), nullable=False),
        sa.Column("old_memory", sa.Text(), nullable=True),
        sa.Column("new_memory", sa.Text(), nullable=True),
        sa.Column("event", sa.String(32), nullable=True),
        sa.Column("created_at", sa.String(64), nullable=True),
        sa.Column("updated_at", sa.String(64), nullable=True),
        sa.Column("is_deleted", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("actor_id", sa.String(255), nullable=True),
        sa.Column("role", sa.String(32), nullable=True),
    )
    op.create_index("ix_mem0_history_memory_id", "mem0_history", ["memory_id"])

    op.create_table(
        "mem0_messages",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("session_scope", sa.String(255), nullable=False),
        sa.Column("role", sa.String(32), nullable=True),
        sa.Column("content", sa.Text(), nullable=True),
        sa.Column("name", sa.String(255), nullable=True),
        sa.Column("created_at", sa.String(64), nullable=True),
    )
    op.create_index("ix_mem0_messages_session_scope_created", "mem0_messages", ["session_scope", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_mem0_messages_session_scope_created", table_name="mem0_messages")
    op.drop_table("mem0_messages")
    op.drop_index("ix_mem0_history_memory_id", table_name="mem0_history")
    op.drop_table("mem0_history")
