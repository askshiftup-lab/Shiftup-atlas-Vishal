"""Remove the development mock email outbox.

Revision ID: 0002_remove_mock_email_outbox
Revises: 0001_auth_schema
"""
from alembic import op
import sqlalchemy as sa

revision = '0002_remove_mock_email_outbox'
down_revision = '0001_auth_schema'
branch_labels = None
depends_on = None


def upgrade():
    op.drop_table('mock_emails')


def downgrade():
    op.create_table(
        'mock_emails',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('recipient', sa.String(length=254), nullable=False),
        sa.Column('subject', sa.String(length=255), nullable=False),
        sa.Column('body', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
