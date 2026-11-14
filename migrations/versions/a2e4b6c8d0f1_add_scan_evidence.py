"""add scan evidence

Revision ID: a2e4b6c8d0f1
Revises: f2f9468a7a48
Create Date: 2026-11-14 16:35:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a2e4b6c8d0f1'
down_revision = 'f2f9468a7a48'
branch_labels = None
depends_on = None


def upgrade():
    # 1. Create network_scan_evidence table
    op.create_table(
        'network_scan_evidence',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('network_scan_id', sa.Integer(), nullable=False),
        sa.Column('phase', sa.String(length=50), nullable=False),
        sa.Column('command', sa.Text(), nullable=True),
        sa.Column('exit_code', sa.Integer(), nullable=True),
        sa.Column('duration_seconds', sa.Float(), nullable=True),
        sa.Column('raw_xml', sa.Text(), nullable=True),
        sa.Column('stderr', sa.Text(), nullable=True),
        sa.Column('nmap_version', sa.String(length=50), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['network_scan_id'], ['network_scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('network_scan_evidence', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_network_scan_evidence_network_scan_id'), ['network_scan_id'], unique=False)

    # 2. Add nullable Text column evidence_json to scans table
    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.add_column(sa.Column('evidence_json', sa.Text(), nullable=True))


def downgrade():
    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.drop_column('evidence_json')

    with op.batch_alter_table('network_scan_evidence', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_network_scan_evidence_network_scan_id'))
    op.drop_table('network_scan_evidence')
