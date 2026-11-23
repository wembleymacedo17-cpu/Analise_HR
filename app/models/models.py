from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Boolean, Date, DateTime, Text,
    ForeignKey, CheckConstraint, UniqueConstraint, Index
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class Unidade(Base):
    __tablename__ = "unidades"
    id = Column(Integer, primary_key=True)
    codigo_unidade = Column(String(20), unique=True, nullable=False)
    nome = Column(String(120), nullable=False)
    ativo = Column(Boolean, default=True, nullable=False)


class CentroCusto(Base):
    __tablename__ = "centros_custo"
    __table_args__ = (
        Index("ix_centros_custo_unidade_id", "unidade_id"),
        Index("ix_centros_custo_ativo_nome", "ativo", "nome"),
    )

    id = Column(Integer, primary_key=True)
    codigo_cc = Column(String(30), unique=True, nullable=False, index=True)
    nome = Column(String(150), nullable=False)
    unidade_id = Column(Integer, ForeignKey("unidades.id", ondelete="RESTRICT"), nullable=False)
    ativo = Column(Boolean, default=True, nullable=False)

    unidade = relationship("Unidade")


class Cargo(Base):
    __tablename__ = "cargos"
    id = Column(Integer, primary_key=True)
    codigo_cargo = Column(String(30), unique=True, nullable=False)
    titulo = Column(String(120), nullable=False)


class Colaborador(Base):
    __tablename__ = "colaboradores"
    __table_args__ = (
        Index("ix_colaboradores_cc_ativo", "centro_custo_id", "ativo"),
        Index("ix_colaboradores_cargo_id", "cargo_id"),
        Index("ix_colaboradores_nome", "nome"),
    )

    id = Column(Integer, primary_key=True)
    cracha = Column(String(20), unique=True, nullable=False, index=True)
    nome = Column(String(150), nullable=False)
    sexo = Column(String(10), nullable=True)
    cpf = Column(String(11), unique=True, nullable=False, index=True)
    data_nascimento = Column(Date, nullable=False)
    email = Column(String(150), nullable=True)
    cargo_id = Column(Integer, ForeignKey("cargos.id", ondelete="RESTRICT"), nullable=False)
    centro_custo_id = Column(Integer, ForeignKey("centros_custo.id", ondelete="RESTRICT"), nullable=False)
    ativo = Column(Boolean, default=True, nullable=False)

    cargo = relationship("Cargo")
    centro_custo = relationship("CentroCusto")


class Usuario(Base):
    __tablename__ = "usuarios"
    __table_args__ = (
        CheckConstraint("role IN ('ROOT', 'GESTOR')", name="ck_role_usuario"),
        Index("ix_usuarios_role_ativo", "role", "ativo"),
    )

    id = Column(Integer, primary_key=True)
    colaborador_id = Column(Integer, ForeignKey("colaboradores.id", ondelete="RESTRICT"), unique=True, nullable=False)
    senha_hash = Column(String(255), nullable=True)
    role = Column(String(20), default="GESTOR", nullable=False)
    ativo = Column(Boolean, default=True, nullable=False)
    session_token = Column(String(64), nullable=True, index=True)
    ultimo_acesso_em = Column(DateTime(timezone=True), nullable=True)
    criado_em = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    colaborador = relationship("Colaborador")
    centros_custo = relationship("UsuarioCentroCusto", back_populates="usuario", cascade="all, delete-orphan")


class UsuarioCentroCusto(Base):
    __tablename__ = "usuario_centros_custo"
    __table_args__ = (
        Index("ix_usuario_cc_centro_custo_id", "centro_custo_id"),
    )

    usuario_id = Column(Integer, ForeignKey("usuarios.id", ondelete="CASCADE"), primary_key=True)
    centro_custo_id = Column(Integer, ForeignKey("centros_custo.id", ondelete="CASCADE"), primary_key=True)
    usuario = relationship("Usuario", back_populates="centros_custo")
    centro_custo = relationship("CentroCusto")


class ConviteAcesso(Base):
    __tablename__ = "convites_acesso"
    __table_args__ = (
        CheckConstraint("status IN ('DISPONIVEL', 'UTILIZADO', 'EXPIRADO', 'CANCELADO')", name="ck_status_convite"),
        Index("ix_convites_status_criado", "status", "criado_em"),
        Index("ix_convites_colaborador_id", "colaborador_id"),
    )

    id = Column(Integer, primary_key=True)
    codigo_hash = Column(String(64), unique=True, nullable=False, index=True)
    colaborador_id = Column(Integer, ForeignKey("colaboradores.id", ondelete="RESTRICT"), nullable=False)
    email_destino = Column(String(150), nullable=False)
    status = Column(String(20), default="DISPONIVEL", nullable=False)
    expira_em = Column(DateTime(timezone=True), nullable=False)
    criado_por_id = Column(Integer, ForeignKey("usuarios.id", ondelete="RESTRICT"), nullable=False)
    criado_em = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    utilizado_em = Column(DateTime(timezone=True), nullable=True)

    colaborador = relationship("Colaborador")
    centros_custo = relationship("ConviteCentroCusto", back_populates="convite", cascade="all, delete-orphan")


class ConviteCentroCusto(Base):
    __tablename__ = "convite_centros_custo"
    __table_args__ = (
        Index("ix_convite_cc_centro_custo_id", "centro_custo_id"),
    )

    convite_id = Column(Integer, ForeignKey("convites_acesso.id", ondelete="CASCADE"), primary_key=True)
    centro_custo_id = Column(Integer, ForeignKey("centros_custo.id", ondelete="CASCADE"), primary_key=True)

    convite = relationship("ConviteAcesso", back_populates="centros_custo")
    centro_custo = relationship("CentroCusto")


class OcorrenciaFalta(Base):
    __tablename__ = "ocorrencias_faltas"
    __table_args__ = (
        UniqueConstraint("colaborador_id", "data_ocorrencia", name="uq_colaborador_data_falta"),
        CheckConstraint("status IN ('PENDENTE', 'ANALISADA')", name="ck_status_ocorrencia"),
        Index("ix_ocorrencias_status_data", "status", "data_ocorrencia"),
        Index("ix_ocorrencias_cc_status_data", "centro_custo_id", "status", "data_ocorrencia"),
    )

    id = Column(Integer, primary_key=True)
    colaborador_id = Column(Integer, ForeignKey("colaboradores.id", ondelete="RESTRICT"), nullable=False)
    centro_custo_id = Column(Integer, ForeignKey("centros_custo.id", ondelete="RESTRICT"), nullable=False)
    data_ocorrencia = Column(Date, nullable=False, index=True)
    status = Column(String(20), default="PENDENTE", nullable=False)
    importado_em = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    colaborador = relationship("Colaborador")
    centro_custo = relationship("CentroCusto")
    analise = relationship("AnaliseFalta", back_populates="ocorrencia", uselist=False, cascade="all, delete-orphan")


class AnaliseFalta(Base):
    __tablename__ = "analises_faltas"
    __table_args__ = (
        CheckConstraint(
            "NOT (autorizado_hora_extra = FALSE AND conseguiu_he_cobertura = TRUE)",
            name="ck_consistencia_hora_extra_cobertura",
        ),
        Index("ix_analises_avaliador_id", "avaliador_id"),
        Index("ix_analises_respondido_em", "respondido_em"),
        Index("ix_analises_cobridor_id", "cobridor_colaborador_id"),
    )

    id = Column(Integer, primary_key=True)
    ocorrencia_id = Column(Integer, ForeignKey("ocorrencias_faltas.id", ondelete="CASCADE"), unique=True, nullable=False)
    avaliador_id = Column(Integer, ForeignKey("usuarios.id", ondelete="RESTRICT"), nullable=False)
    ausencia_programada = Column(Boolean, default=False, nullable=False)
    comunicada_2h_antecedencia = Column(Boolean, nullable=True)
    foi_troca_folga = Column(Boolean, default=False, nullable=True)
    autorizado_hora_extra = Column(Boolean, nullable=True)
    autorizador_he_nome = Column(String(150), nullable=True)
    conseguiu_he_cobertura = Column(Boolean, nullable=True)
    cobridor_colaborador_id = Column(Integer, ForeignKey("colaboradores.id", ondelete="RESTRICT"), nullable=True)
    cobridor_centro_custo_id = Column(Integer, ForeignKey("centros_custo.id", ondelete="RESTRICT"), nullable=True)
    redividiu_equipe = Column(Boolean, nullable=True)
    qtd_pacientes = Column(Integer, nullable=True)
    qtd_colaboradores = Column(Integer, nullable=True)
    justificativa_nao_redimensionada = Column(Text, nullable=True)
    respondido_em = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    ocorrencia = relationship("OcorrenciaFalta", back_populates="analise")
    avaliador = relationship("Usuario")
    cobridor = relationship("Colaborador", foreign_keys=[cobridor_colaborador_id])
    cobridor_centro_custo = relationship("CentroCusto", foreign_keys=[cobridor_centro_custo_id])


class LogEnvioEmail(Base):
    __tablename__ = "logs_envio_email"
    __table_args__ = (
        CheckConstraint("status_envio IN ('ENVIADO', 'ERRO')", name="ck_status_log_email"),
        Index("ix_logs_email_convite_id", "convite_id"),
    )

    id = Column(Integer, primary_key=True)
    convite_id = Column(Integer, ForeignKey("convites_acesso.id", ondelete="CASCADE"), nullable=False)
    destinatario = Column(String(150), nullable=False)
    status_envio = Column(String(20), nullable=False)
    detalhe_erro = Column(Text, nullable=True)
    tentativa_em = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class HistoricoAnaliseDesfeita(Base):
    __tablename__ = "historico_analises_desfeitas"
    __table_args__ = (
        Index("ix_hist_desfeitas_ocorrencia_id", "ocorrencia_id"),
        Index("ix_hist_desfeitas_usuario_id", "desfeito_por_id"),
    )

    id = Column(Integer, primary_key=True)
    ocorrencia_id = Column(Integer, ForeignKey("ocorrencias_faltas.id", ondelete="CASCADE"), nullable=False)
    colaborador_id = Column(Integer, ForeignKey("colaboradores.id", ondelete="CASCADE"), nullable=False)
    centro_custo_id = Column(Integer, ForeignKey("centros_custo.id", ondelete="CASCADE"), nullable=False)
    data_ocorrencia = Column(Date, nullable=False)
    desfeito_por_id = Column(Integer, ForeignKey("usuarios.id", ondelete="CASCADE"), nullable=False)
    motivo = Column(Text, nullable=False)
    dados_analise_anterior = Column(Text, nullable=True)
    desfeito_em = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)    