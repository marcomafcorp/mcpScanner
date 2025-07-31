"""Add audit log table

Revision ID: f6ccedffc31a
Revises: 32cc69794382
Create Date: 2025-07-31 13:31:24.043469

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f6ccedffc31a'
down_revision: Union[str, Sequence[str], None] = '32cc69794382'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Create audit_logs table
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('actor_id', sa.String(36), nullable=True, index=True, comment='User ID who performed the action'),
        sa.Column('actor_email', sa.String(255), nullable=True, comment='Email of the actor for reference'),
        sa.Column('actor_role', sa.String(50), nullable=True, comment='Role of the actor at time of action'),
        sa.Column('action', sa.String(100), nullable=False, index=True, comment='Action performed (e.g., \'user.login\', \'scan.create\')'),
        sa.Column('resource_type', sa.String(50), nullable=True, index=True, comment='Type of resource affected (e.g., \'user\', \'scan\', \'finding\')'),
        sa.Column('resource_id', sa.String(36), nullable=True, index=True, comment='ID of the affected resource'),
        sa.Column('ip_address', sa.String(45), nullable=True, index=True, comment='IP address of the request'),
        sa.Column('user_agent', sa.Text(), nullable=True, comment='User agent string'),
        sa.Column('request_method', sa.String(10), nullable=True, comment='HTTP method (GET, POST, etc.)'),
        sa.Column('request_path', sa.String(500), nullable=True, comment='Request path'),
        sa.Column('response_status', sa.Integer(), nullable=True, comment='HTTP response status code'),
        sa.Column('response_time_ms', sa.Integer(), nullable=True, comment='Response time in milliseconds'),
        sa.Column('details', sa.JSON(), nullable=True, comment='Additional details about the action'),
        sa.Column('error_message', sa.Text(), nullable=True, comment='Error message if action failed'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes
    op.create_index('idx_audit_logs_actor_action', 'audit_logs', ['actor_id', 'action'])
    op.create_index('idx_audit_logs_resource', 'audit_logs', ['resource_type', 'resource_id'])
    op.create_index('idx_audit_logs_timestamp', 'audit_logs', ['created_at'])
    op.create_index('idx_audit_logs_ip_timestamp', 'audit_logs', ['ip_address', 'created_at'])


def downgrade() -> None:
    """Downgrade schema."""
    # Drop indexes
    op.drop_index('idx_audit_logs_ip_timestamp', table_name='audit_logs')
    op.drop_index('idx_audit_logs_timestamp', table_name='audit_logs')
    op.drop_index('idx_audit_logs_resource', table_name='audit_logs')
    op.drop_index('idx_audit_logs_actor_action', table_name='audit_logs')
    
    # Drop table
    op.drop_table('audit_logs')
