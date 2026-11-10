"""Track creation and last update timestamps for persisted entities.

Revision ID: 0003_entity_timestamps
Revises: 0002_remove_mock_email_outbox
"""
from alembic import op
import sqlalchemy as sa

revision = '0003_entity_timestamps'
down_revision = '0002_remove_mock_email_outbox'
branch_labels = None
depends_on = None

_TABLES_WITH_CREATED_AT = (
    'users',
    'email_verifications',
    'auth_sessions',
    'password_resets',
)


def upgrade():
    for table in _TABLES_WITH_CREATED_AT:
        op.add_column(
            table,
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        )
        op.execute(sa.text(f'UPDATE {table} SET updated_at = created_at'))
        with op.batch_alter_table(table) as batch_op:
            batch_op.alter_column(
                'updated_at',
                existing_type=sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            )

    op.add_column(
        'rate_limits',
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        'rate_limits',
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.execute(sa.text(
        'UPDATE rate_limits SET created_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP'
    ))
    with op.batch_alter_table('rate_limits') as batch_op:
        batch_op.alter_column(
            'created_at',
            existing_type=sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        )
        batch_op.alter_column(
            'updated_at',
            existing_type=sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        )


def downgrade():
    op.drop_column('rate_limits', 'updated_at')
    op.drop_column('rate_limits', 'created_at')
    for table in reversed(_TABLES_WITH_CREATED_AT):
        op.drop_column(table, 'updated_at')
