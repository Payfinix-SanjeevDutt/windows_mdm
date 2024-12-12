"""empty message

Revision ID: d7dea7521d77
Revises: 
Create Date: 2024-12-08 09:21:35.992818

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd7dea7521d77'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('device',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('device_id', sa.String(), nullable=False),
    sa.Column('device_name', sa.String(), nullable=False),
    sa.Column('enrolled_at', sa.DateTime(), server_default=sa.text('now()'), nullable=True),
    sa.Column('compliance_status', sa.String(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('device_id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('device')
    # ### end Alembic commands ###
