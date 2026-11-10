"""Allow phone numbers to be stored in normalized international format.

Revision ID: 0005_phone_number_ten_digits
Revises: 0004_user_profile_fields
"""
from alembic import op
import sqlalchemy as sa

revision = '0005_phone_number_ten_digits'
down_revision = '0004_user_profile_fields'
branch_labels = None
depends_on = None


def upgrade():
    op.drop_index('uq_users_email_normalized', table_name='users')
    with op.batch_alter_table('users') as batch_op:
        batch_op.alter_column(
            'phone_number',
            existing_type=sa.String(length=16),
            type_=sa.String(length=16),
            existing_nullable=True,
        )
        batch_op.create_check_constraint(
            'ck_users_phone_number_length',
            'phone_number IS NULL OR length(phone_number) <= 16',
        )
    op.create_index(
        'uq_users_email_normalized',
        'users',
        [sa.text('lower(email)')],
        unique=True,
    )


def downgrade():
    op.drop_index('uq_users_email_normalized', table_name='users')
    with op.batch_alter_table('users') as batch_op:
        batch_op.drop_constraint('ck_users_phone_number_length', type_='check')
        batch_op.alter_column(
            'phone_number',
            existing_type=sa.String(length=16),
            type_=sa.String(length=16),
            existing_nullable=True,
        )
    op.create_index(
        'uq_users_email_normalized',
        'users',
        [sa.text('lower(email)')],
        unique=True,
    )