"""Colunas  novas

Revision ID: b2d52a06db31
Revises: 323dd5ffe0b4
Create Date: 2026-11-26 14:55:51.654467

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b2d52a06db31'
down_revision = '323dd5ffe0b4'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        'programacoes_assistenciais',
        sa.Column('qtd_aux_12h', sa.Integer(), server_default=sa.text('0'), nullable=False),
    )
    op.add_column(
        'programacoes_assistenciais',
        sa.Column('qtd_aux_6h_manha', sa.Integer(), server_default=sa.text('0'), nullable=False),
    )
    op.add_column(
        'programacoes_assistenciais',
        sa.Column('qtd_aux_6h_tarde', sa.Integer(), server_default=sa.text('0'), nullable=False),
    )
    op.add_column(
        'programacoes_assistenciais',
        sa.Column('tem_colaboradores_novos', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    )
    op.add_column(
        'programacoes_assistenciais',
        sa.Column('qtd_colaboradores_novos', sa.Integer(), server_default=sa.text('0'), nullable=False),
    )
    op.add_column(
        'programacoes_assistenciais',
        sa.Column('pacientes_colaboradores_novos', sa.Integer(), server_default=sa.text('0'), nullable=False),
    )
    op.add_column(
        'programacoes_assistenciais',
        sa.Column('detalhe_colaboradores_novos', sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column('programacoes_assistenciais', 'detalhe_colaboradores_novos')
    op.drop_column('programacoes_assistenciais', 'pacientes_colaboradores_novos')
    op.drop_column('programacoes_assistenciais', 'qtd_colaboradores_novos')
    op.drop_column('programacoes_assistenciais', 'tem_colaboradores_novos')
    op.drop_column('programacoes_assistenciais', 'qtd_aux_6h_tarde')
    op.drop_column('programacoes_assistenciais', 'qtd_aux_6h_manha')
    op.drop_column('programacoes_assistenciais', 'qtd_aux_12h')