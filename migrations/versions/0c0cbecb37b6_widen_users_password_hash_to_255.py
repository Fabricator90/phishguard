"""widen users.password_hash to 255 (safe, non-destructive)"""

from alembic import op
import sqlalchemy as sa

# Keep these IDs as they are in your repo/logs
revision = "0c0cbecb37b6"
down_revision = "0b2c091e10de"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)

    # If new table name exists, alter it; otherwise alter legacy "user"
    if insp.has_table("users"):
        op.alter_column(
            "users",
            "password_hash",
            existing_type=sa.String(length=128),
            type_=sa.String(length=255),
            existing_nullable=True,
            nullable=False,
        )
    elif insp.has_table("user"):
        op.alter_column(
            "user",
            "password_hash",
            existing_type=sa.String(length=128),
            type_=sa.String(length=255),
            existing_nullable=True,
            nullable=False,
        )
    # Do NOT drop/rename any tables here.


def downgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)

    if insp.has_table("users"):
        op.alter_column(
            "users",
            "password_hash",
            existing_type=sa.String(length=255),
            type_=sa.String(length=128),
            existing_nullable=False,
            nullable=True,
        )
    elif insp.has_table("user"):
        op.alter_column(
            "user",
            "password_hash",
            existing_type=sa.String(length=255),
            type_=sa.String(length=128),
            existing_nullable=False,
            nullable=True,
        )
