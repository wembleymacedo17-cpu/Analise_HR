import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from flask import Blueprint, jsonify, request, session
from sqlalchemy import func, case
from sqlalchemy.orm import joinedload, selectinload, load_only
from werkzeug.security import check_password_hash, generate_password_hash

from app import get_db
from app.models.models import (
    Colaborador, CentroCusto, Cargo, Usuario, UsuarioCentroCusto,
    ConviteAcesso, ConviteCentroCusto, OcorrenciaFalta, AnaliseFalta
)
from app.services.etl_estrutura import ETLEstruturaSenior
from app.services.etl_faltas import ETLFaltasDiario

api_bp = Blueprint('api', __name__, url_prefix='/api')


def _obter_ccs_usuario(db, usuario_id: int) -> list[int]:
    """Busca apenas os IDs dos centros de custo diretamente pela PK composta (sem carregar objetos ORM)."""
    rows = (
        db.query(UsuarioCentroCusto.centro_custo_id)
        .filter(UsuarioCentroCusto.usuario_id == usuario_id)
        .all()
    )
    return [r[0] for r in rows]


# ==============================================================================
# AUTENTICAÇÃO E PRIMEIRO ACESSO
# ==============================================================================
@api_bp.route('/login', methods=['POST'])
def login_api():
    data = request.json or {}
    cracha = str(data.get('cracha', '')).strip()
    senha = str(data.get('senha', '')).strip()

    if not cracha or not senha:
        return jsonify({'sucesso': False, 'mensagem': 'Informe o crachá e a senha.'}), 400

    db = get_db()
    # Busca direta via índice único de colaboradores.cracha + JOIN em usuarios
    row = (
        db.query(
            Usuario.id,
            Usuario.senha_hash,
            Usuario.role,
            Usuario.ativo,
            Colaborador.nome,
            Colaborador.cracha
        )
        .join(Colaborador, Usuario.colaborador_id == Colaborador.id)
        .filter(Colaborador.cracha == cracha, Colaborador.ativo.is_(True))
        .first()
    )

    if not row or not row.ativo or not row.senha_hash or not check_password_hash(row.senha_hash, senha):
        return jsonify({'sucesso': False, 'mensagem': 'Crachá ou senha incorretos.'}), 401

    session.clear()
    session.permanent = True
    session['usuario_id'] = row.id
    session['usuario_nome'] = row.nome
    session['cracha'] = row.cracha
    session['usuario_perfil'] = (row.role or 'GESTOR').strip().upper()

    return jsonify({
        'sucesso': True,
        'mensagem': 'Login efetuado com sucesso!',
        'usuario': {
            'id': row.id,
            'nome': row.nome,
            'cracha': row.cracha,
            'perfil': session['usuario_perfil']
        }
    }), 200


@api_bp.route('/logout', methods=['POST', 'GET'])
def logout_api():
    session.clear()
    return jsonify({'sucesso': True, 'mensagem': 'Sessão encerrada com sucesso.'}), 200


@api_bp.route('/primeiro-acesso', methods=['POST'])
def primeiro_acesso_api():
    data = request.json or {}
    codigo_raw = str(data.get('codigo_convite', '')).strip().upper()
    cpf = ''.join(filter(str.isdigit, str(data.get('cpf', '')))).zfill(11)
    nova_senha = str(data.get('senha', '')).strip()

    if not codigo_raw or len(cpf) != 11 or len(nova_senha) < 6:
        return jsonify({'sucesso': False, 'mensagem': 'Preencha todos os campos (senha mínima de 6 caracteres).'}), 400

    db = get_db()
    codigo_hash = hashlib.sha256(codigo_raw.encode('utf-8')).hexdigest()
    agora = datetime.now(timezone.utc)

    # Busca pelo índice único codigo_hash já trazendo colaborador e centros de custo
    convite = (
        db.query(ConviteAcesso)
        .options(
            joinedload(ConviteAcesso.colaborador).load_only(Colaborador.id, Colaborador.cpf),
            selectinload(ConviteAcesso.centros_custo)
        )
        .filter(ConviteAcesso.codigo_hash == codigo_hash)
        .with_for_update()
        .first()
    )

    if not convite or convite.status != 'DISPONIVEL' or convite.expira_em < agora:
        db.rollback()
        return jsonify({'sucesso': False, 'mensagem': 'Código de convite inválido, já utilizado ou expirado.'}), 400

    if convite.colaborador.cpf != cpf:
        db.rollback()
        return jsonify({'sucesso': False, 'mensagem': 'O CPF informado não corresponde ao titular do convite.'}), 400

    usuario = db.query(Usuario).filter(Usuario.colaborador_id == convite.colaborador_id).first()
    if not usuario:
        usuario = Usuario(
            colaborador_id=convite.colaborador_id,
            senha_hash=generate_password_hash(nova_senha),
            role='GESTOR',
            ativo=True
        )
        db.add(usuario)
        db.flush()
    else:
        usuario.senha_hash = generate_password_hash(nova_senha)
        usuario.ativo = True

    ccs_atuais = set(_obter_ccs_usuario(db, usuario.id))
    for cc_convite in convite.centros_custo:
        if cc_convite.centro_custo_id not in ccs_atuais:
            db.add(UsuarioCentroCusto(usuario_id=usuario.id, centro_custo_id=cc_convite.centro_custo_id))

    convite.status = 'UTILIZADO'
    convite.utilizado_em = agora
    db.commit()

    return jsonify({'sucesso': True, 'mensagem': 'Acesso ativado com sucesso! Você já pode fazer login.'}), 200


# ==============================================================================
# OPERACIONAL DE FALTAS (GESTOR & ROOT) - CONSULTA ÚNICA SEM N+1
# ==============================================================================
@api_bp.route('/faltas', methods=['GET'])
def listar_faltas():
    id_user = session.get('usuario_id')
    perfil = session.get('usuario_perfil')
    if not id_user:
        return jsonify({'sucesso': False, 'mensagem': 'Não autenticado.'}), 401

    db = get_db()
    status_filtro = request.args.get('status', 'PENDENTE').upper()

    # Consulta única com JOIN explícito nas tabelas envolvidas (evita centenas de roundtrips no RDS)
    query = (
        db.query(
            OcorrenciaFalta.id,
            OcorrenciaFalta.data_ocorrencia,
            OcorrenciaFalta.status,
            Colaborador.cracha,
            Colaborador.nome.label('colaborador_nome'),
            Cargo.titulo.label('cargo_titulo'),
            CentroCusto.codigo_cc,
            CentroCusto.nome.label('centro_custo_nome')
        )
        .join(Colaborador, OcorrenciaFalta.colaborador_id == Colaborador.id)
        .join(CentroCusto, OcorrenciaFalta.centro_custo_id == CentroCusto.id)
        .outerjoin(Cargo, Colaborador.cargo_id == Cargo.id)
        .filter(OcorrenciaFalta.status == status_filtro)
    )

    if perfil != 'ROOT':
        cc_ids = _obter_ccs_usuario(db, id_user)
        if not cc_ids:
            return jsonify({'sucesso': True, 'faltas': []}), 200
        # Aproveita o índice composto ix_ocorrencias_cc_status (centro_custo_id, status)
        query = query.filter(OcorrenciaFalta.centro_custo_id.in_(cc_ids))

    rows = query.order_by(OcorrenciaFalta.data_ocorrencia.desc()).limit(300).all()

    # Se estiver listando ANALISADA, busca os dados de auditoria em um único lote via IN
    analises_map = {}
    if status_filtro == 'ANALISADA' and rows:
        ocorr_ids = [r.id for r in rows]
        analises_rows = (
            db.query(
                AnaliseFalta.ocorrencia_id,
                AnaliseFalta.comunicada_2h_antecedencia,
                AnaliseFalta.foi_troca_folga,
                AnaliseFalta.autorizado_hora_extra,
                AnaliseFalta.conseguiu_he_cobertura,
                AnaliseFalta.redividiu_equipe,
                AnaliseFalta.respondido_em,
                Colaborador.nome.label('avaliador_nome')
            )
            .join(Usuario, AnaliseFalta.avaliador_id == Usuario.id)
            .join(Colaborador, Usuario.colaborador_id == Colaborador.id)
            .filter(AnaliseFalta.ocorrencia_id.in_(ocorr_ids))
            .all()
        )
        for a in analises_rows:
            dt_resp = (a.respondido_em - timedelta(hours=3)).strftime('%d/%m/%Y %H:%M')
            analises_map[a.ocorrencia_id] = {
                'comunicada_2h_antecedencia': a.comunicada_2h_antecedencia,
                'foi_troca_folga': a.foi_troca_folga,
                'autorizado_hora_extra': a.autorizado_hora_extra,
                'conseguiu_he_cobertura': a.conseguiu_he_cobertura,
                'redividiu_equipe': a.redividiu_equipe,
                'avaliador': a.avaliador_nome,
                'respondido_em': dt_resp
            }

    lista = [
        {
            'id': r.id,
            'cracha': r.cracha,
            'colaborador_nome': r.colaborador_nome,
            'cargo': r.cargo_titulo or '---',
            'codigo_cc': r.codigo_cc,
            'centro_custo': r.centro_custo_nome,
            'data_ocorrencia': r.data_ocorrencia.strftime('%d/%m/%Y'),
            'status': r.status,
            'analise': analises_map.get(r.id)
        }
        for r in rows
    ]

    return jsonify({'sucesso': True, 'faltas': lista}), 200


@api_bp.route('/analisar-falta', methods=['POST'])
def analisar_falta():
    id_user = session.get('usuario_id')
    perfil = session.get('usuario_perfil')
    if not id_user:
        return jsonify({'sucesso': False, 'mensagem': 'Não autenticado.'}), 401

    data = request.json or {}
    ocorrencia_id = data.get('ocorrencia_id')
    if not ocorrencia_id:
        return jsonify({'sucesso': False, 'mensagem': 'ID da ocorrência não informado.'}), 400

    comunicada_2h = bool(data.get('comunicada_2h_antecedencia'))
    foi_troca = bool(data.get('foi_troca_folga'))
    autorizado_he = bool(data.get('autorizado_hora_extra'))
    conseguiu_he = bool(data.get('conseguiu_he_cobertura'))
    redividiu = bool(data.get('redividiu_equipe'))

    if not autorizado_he and conseguiu_he:
        return jsonify({
            'sucesso': False,
            'mensagem': 'Inconsistência: não é possível marcar cobertura por Hora Extra sem autorização de HE.'
        }), 400

    db = get_db()
    # Bloqueio pessimista na PK para evitar gravação concorrente
    ocorrencia = (
        db.query(OcorrenciaFalta)
        .filter(OcorrenciaFalta.id == int(ocorrencia_id))
        .with_for_update()
        .first()
    )
    if not ocorrencia:
        db.rollback()
        return jsonify({'sucesso': False, 'mensagem': 'Ocorrência não encontrada.'}), 404

    if perfil != 'ROOT':
        # Verifica permissão direto pelo índice PK (usuario_id, centro_custo_id)
        tem_acesso = (
            db.query(UsuarioCentroCusto.usuario_id)
            .filter(
                UsuarioCentroCusto.usuario_id == id_user,
                UsuarioCentroCusto.centro_custo_id == ocorrencia.centro_custo_id
            )
            .first()
        )
        if not tem_acesso:
            db.rollback()
            return jsonify({'sucesso': False, 'mensagem': 'Sem permissão para analisar este Centro de Custo.'}), 403

    if ocorrencia.status == 'ANALISADA':
        db.rollback()
        return jsonify({'sucesso': False, 'mensagem': 'Esta falta já foi analisada anteriormente.'}), 409

    nova_analise = AnaliseFalta(
        ocorrencia_id=ocorrencia.id,
        avaliador_id=id_user,
        comunicada_2h_antecedencia=comunicada_2h,
        foi_troca_folga=foi_troca,
        autorizado_hora_extra=autorizado_he,
        conseguiu_he_cobertura=conseguiu_he,
        redividiu_equipe=redividiu
    )
    ocorrencia.status = 'ANALISADA'
    db.add(nova_analise)
    db.commit()

    return jsonify({'sucesso': True, 'mensagem': 'Análise registrada com sucesso!'}), 200


# ==============================================================================
# ADMINISTRAÇÃO ROOT (CONVITES, GESTORES, ETL E MÉTRICAS)
# ==============================================================================
@api_bp.route('/centros-custo', methods=['GET'])
def listar_centros_custo():
    if session.get('usuario_perfil') != 'ROOT':
        return jsonify({'sucesso': False, 'mensagem': 'Acesso negado.'}), 403

    db = get_db()
    ccs = (
        db.query(CentroCusto.id, CentroCusto.codigo_cc, CentroCusto.nome)
        .filter(CentroCusto.ativo.is_(True))
        .order_by(CentroCusto.nome.asc())
        .all()
    )
    return jsonify({
        'sucesso': True,
        'centros_custo': [{'id': c.id, 'codigo_cc': c.codigo_cc, 'nome': c.nome} for c in ccs]
    }), 200


@api_bp.route('/convites', methods=['GET', 'POST'])
def convites_api():
    if session.get('usuario_perfil') != 'ROOT':
        return jsonify({'sucesso': False, 'mensagem': 'Acesso negado.'}), 403

    db = get_db()

    if request.method == 'POST':
        data = request.json or {}
        cracha = str(data.get('cracha', '')).strip()
        email_destino = str(data.get('email_destino', '')).strip().lower()
        ccs_ids = data.get('centros_custo_ids', [])
        dias_validade = int(data.get('dias_validade', 7))

        # Busca via índice único colaboradores.cracha
        colab = (
            db.query(Colaborador.id, Colaborador.nome, Colaborador.email)
            .filter(Colaborador.cracha == cracha, Colaborador.ativo.is_(True))
            .first()
        )
        if not colab:
            return jsonify({'sucesso': False, 'mensagem': f'Colaborador com crachá {cracha} não encontrado.'}), 404

        if not ccs_ids:
            return jsonify({'sucesso': False, 'mensagem': 'Selecione ao menos um Centro de Custo.'}), 400

        codigo_plain = secrets.token_hex(4).upper()
        codigo_hash = hashlib.sha256(codigo_plain.encode('utf-8')).hexdigest()

        novo_convite = ConviteAcesso(
            codigo_hash=codigo_hash,
            colaborador_id=colab.id,
            email_destino=email_destino or colab.email or 'sem-email@funfarme.com.br',
            status='DISPONIVEL',
            expira_em=datetime.now(timezone.utc) + timedelta(days=dias_validade),
            criado_por_id=session['usuario_id']
        )
        db.add(novo_convite)
        db.flush()

        db.bulk_save_objects([
            ConviteCentroCusto(convite_id=novo_convite.id, centro_custo_id=int(cc_id))
            for cc_id in set(ccs_ids)
        ])

        db.commit()
        return jsonify({
            'sucesso': True,
            'mensagem': f'Convite gerado para {colab.nome}!',
            'codigo_ativacao': codigo_plain,
            'colaborador': colab.nome
        }), 201

    # Eager loading em lote para evitar N+1 na listagem de convites
    convites = (
        db.query(ConviteAcesso)
        .options(
            joinedload(ConviteAcesso.colaborador).load_only(Colaborador.cracha, Colaborador.nome),
            selectinload(ConviteAcesso.centros_custo)
            .joinedload(ConviteCentroCusto.centro_custo)
            .load_only(CentroCusto.nome)
        )
        .order_by(ConviteAcesso.criado_em.desc())
        .limit(50)
        .all()
    )

    lista = [
        {
            'id': c.id,
            'cracha': c.colaborador.cracha,
            'colaborador': c.colaborador.nome,
            'email_destino': c.email_destino,
            'status': c.status,
            'criado_em': (c.criado_em - timedelta(hours=3)).strftime('%d/%m/%Y %H:%M'),
            'expira_em': (c.expira_em - timedelta(hours=3)).strftime('%d/%m/%Y %H:%M'),
            'centros_custo': [cc.centro_custo.nome for cc in c.centros_custo]
        }
        for c in convites
    ]

    return jsonify({'sucesso': True, 'convites': lista}), 200


@api_bp.route('/gestores', methods=['GET'])
def listar_gestores():
    if session.get('usuario_perfil') != 'ROOT':
        return jsonify({'sucesso': False, 'mensagem': 'Acesso negado.'}), 403

    db = get_db()
    gestores = (
        db.query(Usuario)
        .options(
            joinedload(Usuario.colaborador).load_only(Colaborador.cracha, Colaborador.nome),
            selectinload(Usuario.centros_custo)
            .joinedload(UsuarioCentroCusto.centro_custo)
            .load_only(CentroCusto.nome)
        )
        .filter(Usuario.role == 'GESTOR')
        .all()
    )

    return jsonify({
        'sucesso': True,
        'gestores': [
            {
                'id': g.id,
                'cracha': g.colaborador.cracha,
                'nome': g.colaborador.nome,
                'ativo': g.ativo,
                'centros_custo': [uc.centro_custo.nome for uc in g.centros_custo]
            } for g in gestores
        ]
    }), 200


@api_bp.route('/gestores/<int:usuario_id>/alternar-status', methods=['PUT'])
def alternar_status_gestor(usuario_id):
    if session.get('usuario_perfil') != 'ROOT':
        return jsonify({'sucesso': False, 'mensagem': 'Acesso negado.'}), 403

    db = get_db()
    user = db.query(Usuario).filter(Usuario.id == usuario_id, Usuario.role == 'GESTOR').first()
    if not user:
        return jsonify({'sucesso': False, 'mensagem': 'Gestor não encontrado.'}), 404

    user.ativo = not user.ativo
    db.commit()
    return jsonify({
        'sucesso': True,
        'mensagem': f'Acesso {"ativado" if user.ativo else "bloqueado"} com sucesso!',
        'ativo': user.ativo
    }), 200


@api_bp.route('/etl/executar', methods=['POST'])
def executar_etl():
    if session.get('usuario_perfil') != 'ROOT':
        return jsonify({'sucesso': False, 'mensagem': 'Acesso negado.'}), 403

    data = request.json or {}
    tipo = data.get('tipo', 'faltas')

    try:
        if tipo == 'estrutura':
            ETLEstruturaSenior().executar()
            return jsonify({'sucesso': True, 'mensagem': 'Carga de estrutura e colaboradores concluída!'}), 200
        else:
            ETLFaltasDiario(dias_retroativos=15).executar()
            return jsonify({'sucesso': True, 'mensagem': 'Carga diária de faltas (D-1) concluída!'}), 200
    except Exception as e:
        return jsonify({'sucesso': False, 'mensagem': f'Erro ao executar ETL: {str(e)}'}), 500


@api_bp.route('/dashboard/metricas', methods=['GET'])
def dashboard_metricas():
    if session.get('usuario_perfil') != 'ROOT':
        return jsonify({'sucesso': False, 'mensagem': 'Acesso negado.'}), 403

    db = get_db()
    # Agregação condicional única no índice de status (evita 2 varreduras separadas)
    stats_faltas = db.query(
        func.count(case((OcorrenciaFalta.status == 'PENDENTE', 1))).label('pendentes'),
        func.count(case((OcorrenciaFalta.status == 'ANALISADA', 1))).label('analisadas')
    ).first()

    total_gestores = db.query(func.count(Usuario.id)).filter(Usuario.role == 'GESTOR', Usuario.ativo.is_(True)).scalar() or 0
    convites_ativos = db.query(func.count(ConviteAcesso.id)).filter(ConviteAcesso.status == 'DISPONIVEL').scalar() or 0

    return jsonify({
        'sucesso': True,
        'kpis': {
            'pendentes': stats_faltas.pendentes or 0,
            'analisadas': stats_faltas.analisadas or 0,
            'gestores_ativos': total_gestores,
            'convites_disponiveis': convites_ativos
        }
    }), 200