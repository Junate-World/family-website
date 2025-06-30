"""Add ownership tracking

Revision ID: add_ownership_tracking
Revises: 3093d940eda1
Create Date: 2025-06-30 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_ownership_tracking'
down_revision = '3093d940eda1'
branch_labels = None
depends_on = None


def upgrade():
    # Add created_by column to family_member table
    with op.batch_alter_table('family_member', schema=None) as batch_op:
        batch_op.add_column(sa.Column('created_by', sa.Integer(), nullable=True))
        batch_op.create_foreign_key('fk_family_member_created_by', 'user', ['created_by'], ['id'])
    
    # Set default ownership for existing members (assign to first user)
    op.execute("UPDATE family_member SET created_by = (SELECT id FROM user LIMIT 1) WHERE created_by IS NULL;")
    
    # Make created_by NOT NULL after setting default values
    with op.batch_alter_table('family_member', schema=None) as batch_op:
        batch_op.alter_column('created_by', nullable=False)


def downgrade():
    with op.batch_alter_table('family_member', schema=None) as batch_op:
        batch_op.drop_constraint('fk_family_member_created_by', type_='foreignkey')
        batch_op.drop_column('created_by') 