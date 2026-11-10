"""Enforce unique identities for external authentication providers.

Revision ID: 0007_unique_provider_identity
Revises: 0006_social_auth_providers
"""
from alembic import op
import sqlalchemy as sa

revision = '0007_unique_provider_identity'
down_revision = '0006_social_auth_providers'
branch_labels = None
depends_on = None


def upgrade():
    op.create_index(
        'uq_users_provider_identity',
        'users',
        ['auth_provider', 'provider_user_id'],
        unique=True,
        sqlite_where=sa.text('provider_user_id IS NOT NULL'),
        postgresql_where=sa.text('provider_user_id IS NOT NULL'),
    )


def downgrade():
    op.drop_index('uq_users_provider_identity', table_name='users')
