"""Add one-time OAuth nonce challenges.

Revision ID: 0008_oauth_challenges
Revises: 0007_unique_provider_identity
"""
from alembic import op
import sqlalchemy as sa

revision = '0008_oauth_challenges'
down_revision = '0007_unique_provider_identity'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'oauth_challenges',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('auth_provider', sa.String(length=16), nullable=False),
        sa.Column('nonce_digest', sa.String(length=64), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('consumed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(
            "auth_provider IN ('google', 'apple')",
            name='ck_oauth_challenges_provider',
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('nonce_digest'),
    )
    op.create_index(
        'ix_oauth_challenges_expires_at',
        'oauth_challenges',
        ['expires_at'],
    )


def downgrade():
    op.drop_index('ix_oauth_challenges_expires_at', table_name='oauth_challenges')
    op.drop_table('oauth_challenges')
