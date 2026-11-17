"""add network exposure rule columns to network_scan_results

Revision ID: c4d6e8f0a1b2
Revises: a2e4b6c8d0f1
Create Date: 2026-11-15 17:15:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c4d6e8f0a1b2'
down_revision = 'a2e4b6c8d0f1'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('network_scan_results', schema=None) as batch_op:
        batch_op.add_column(sa.Column('rule_id', sa.String(length=50), nullable=True))
        batch_op.add_column(sa.Column('observation', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('rationale', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('basis', sa.String(length=100), nullable=True))


def downgrade():
    with op.batch_alter_table('network_scan_results', schema=None) as batch_op:
        batch_op.drop_column('basis')
        batch_op.drop_column('rationale')
        batch_op.drop_column('observation')
        batch_op.drop_column('rule_id')
