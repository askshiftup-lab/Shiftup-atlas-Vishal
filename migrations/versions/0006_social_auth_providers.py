"""Add optional Google and Apple auth provider tracking to user records.

Revision ID: 0006_social_auth_providers
Revises: 0005_phone_number_ten_digits
"""
from alembic import op
import sqlalchemy as sa

revision = '0006_social_auth_providers'
down_revision = '0005_phone_number_ten_digits'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('users') as batch_op:
        batch_op.add_column(
            sa.Column('auth_provider', sa.String(length=16), nullable=False, server_default='email'),
        )
        batch_op.add_column(
            sa.Column('provider_user_id', sa.String(length=255), nullable=True),
        )
        batch_op.create_check_constraint(
            'ck_users_auth_provider',
            "auth_provider IN ('email', 'google', 'apple')",
        )


def downgrade():
    with op.batch_alter_table('users') as batch_op:
        batch_op.drop_constraint('ck_users_auth_provider', type_='check')
        batch_op.drop_column('provider_user_id')
        batch_op.drop_column('auth_provider')
