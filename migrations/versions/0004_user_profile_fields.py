"""Align user records with the approved profile fields.

Revision ID: 0004_user_profile_fields
Revises: 0003_entity_timestamps
"""
from alembic import op
import sqlalchemy as sa

revision = '0004_user_profile_fields'
down_revision = '0003_entity_timestamps'
branch_labels = None
depends_on = None


def _rename_column(table: str, old_name: str, new_name: str) -> None:
    if op.get_bind().dialect.name == 'sqlite':
        op.execute(sa.text(f'ALTER TABLE {table} RENAME COLUMN {old_name} TO {new_name}'))
    else:
        op.alter_column(table, old_name, new_column_name=new_name)


def upgrade():
    _rename_column('users', 'id', 'user_id')
    _rename_column('users', 'phone_e164', 'phone_number')

    op.add_column(
        'users',
        sa.Column('phone_verified_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        'users',
        sa.Column(
            'account_status',
            sa.String(length=16),
            sa.CheckConstraint(
                "account_status IN ('pending', 'active', 'disabled')",
                name='ck_users_account_status',
            ),
            nullable=False,
            server_default='pending',
        ),
    )
    op.execute(sa.text(
        "UPDATE users SET account_status = CASE "
        "WHEN is_active = 0 THEN 'disabled' "
        "WHEN email_verified_at IS NOT NULL THEN 'active' "
        "ELSE 'pending' END"
    ))
    op.drop_column('users', 'is_active')

    op.drop_index('ix_users_email', table_name='users')
    op.create_index(
        'uq_users_email_normalized',
        'users',
        [sa.text('lower(email)')],
        unique=True,
    )


def downgrade():
    op.drop_index('uq_users_email_normalized', table_name='users')
    op.create_index('ix_users_email', 'users', ['email'], unique=True)
    op.add_column(
        'users',
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.execute(sa.text("UPDATE users SET is_active = CASE WHEN account_status = 'disabled' THEN 0 ELSE 1 END"))
    op.drop_column('users', 'account_status')
    op.drop_column('users', 'phone_verified_at')
    _rename_column('users', 'phone_number', 'phone_e164')
    _rename_column('users', 'user_id', 'id')
