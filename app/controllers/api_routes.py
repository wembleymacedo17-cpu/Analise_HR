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
    ConviteAcesso, ConviteCentroCusto, OcorrenciaFalta, AnaliseFalta,
    LogEnvioEmail
)
from app.services.etl_estrutura import ETLEstruturaSenior
from app.services.etl_faltas import ETLFaltasDiario
from app.services.notificador_email import NotificadorEmail

api_bp = Blueprint('api', __name__, url_prefix='/api')


def _obter_ccs_usuario(db, usuario_id: int) -> list[int]:
    """Busca apenas os IDs dos centros de custo diretamente pela PK composta."""
    rows = (
        db.query(UsuarioCentroCusto.centro_custo_id)
        .filter(UsuarioCentroCusto.usuario_id == usuario_id)
        .all()
    )
    return [r[0] for r in rows]


def _expirar_convites_vencidos(db, colaborador_id: int | None = None):
    """Atualiza convites DISPONIVEL com data expirada para EXPIRADO."""
    agora = datetime.now(timezone.utc)
    q = db.query(ConviteAcesso).filter(
        ConviteAcesso.status == 'DISPONIVEL',
        ConviteAcesso.expira_em < agora
    )
    if colaborador_id is not None:
        q = q.filter(ConviteAcesso.colaborador_id == colaborador_id)
    q.update({'status': 'EXPIRADO'}, synchronize_session=False)


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

    convite = (
        db.query(ConviteAcesso)
        .options(
            joinedload(ConviteAcesso.colaborador).load_only(Colaborador.id, Colaborador.cpf),
            selectinload(ConviteAcesso.centros_custo)
        )
        .filter(ConviteAcesso.codigo_hash == codigo_hash)
        .with_for_update(of=ConviteAcesso)
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

    return jsonify({'sucesso': True, 'mensagem': 'Acesso ativado com sucesso!'}), 200


# ==============================================================================
# OPERACIONAL DE OCORRÊNCIAS (GESTOR & ROOT)
# ==============================================================================
@api_bp.route('/faltas', methods=['GET'])
def listar_faltas():
    id_user = session.get('usuario_id')
    perfil = session.get('usuario_perfil')
    if not id_user:
        return jsonify({'sucesso': False, 'mensagem': 'Não autenticado.'}), 401

    db = get_db()
    status_filtro = request.args.get('status', 'PENDENTE').upper()

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
        query = query.filter(OcorrenciaFalta.centro_custo_id.in_(cc_ids))

    rows = query.order_by(OcorrenciaFalta.data_ocorrencia.desc()).limit(300).all()

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
            'mensagem': 'Não é possível marcar cobertura por Hora Extra sem autorização de HE.'
        }), 400

    db = get_db()
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
        return jsonify({'sucesso': False, 'mensagem': 'Esta ocorrência já foi analisada.'}), 409

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
# ADMINISTRAÇÃO ROOT (VALIDAÇÃO CRACHÁ, CONVITES, GESTORES, ETL E MÉTRICAS)
# ==============================================================================
@api_bp.route('/colaboradores/<string:cracha>', methods=['GET'])
def validar_cracha_colaborador(cracha):
    """Valida se o crachá existe, está ativo e se já não possui uma hash DISPONIVEL."""
    if session.get('usuario_perfil') != 'ROOT':
        return jsonify({'sucesso': False, 'mensagem': 'Acesso negado.'}), 403

    cracha_limpo = str(cracha).strip()
    if not cracha_limpo:
        return jsonify({'sucesso': False, 'mensagem': 'Informe o crachá.'}), 400

    db = get_db()
    row = (
        db.query(
            Colaborador.id,
            Colaborador.cracha,
            Colaborador.nome,
            Colaborador.email,
            CentroCusto.nome.label('setor_atual')
        )
        .join(CentroCusto, Colaborador.centro_custo_id == CentroCusto.id)
        .filter(Colaborador.cracha == cracha_limpo, Colaborador.ativo.is_(True))
        .first()
    )

    if not row:
        return jsonify({
            'sucesso': False,
            'mensagem': f'Crachá "{cracha_limpo}" não encontrado ou colaborador inativo.'
        }), 404

    _expirar_convites_vencidos(db, row.id)
    db.commit()

    convite_ativo = (
        db.query(ConviteAcesso.id, ConviteAcesso.email_destino)
        .filter(
            ConviteAcesso.colaborador_id == row.id,
            ConviteAcesso.status == 'DISPONIVEL'
        )
        .first()
    )

    if convite_ativo:
        return jsonify({
            'sucesso': False,
            'convite_duplicado': True,
            'mensagem': f'Já existe uma hash DISPONÍVEL para o crachá {cracha_limpo} ({row.nome}). Reenvie ou remova a atual no Histórico.'
        }), 409

    return jsonify({
        'sucesso': True,
        'colaborador': {
            'id': row.id,
            'cracha': row.cracha,
            'nome': row.nome,
            'email': row.email or '',
            'setor_atual': row.setor_atual
        }
    }), 200


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

        if not cracha:
            return jsonify({'sucesso': False, 'mensagem': 'Informe o crachá do gestor.'}), 400

        if not email_destino or '@' not in email_destino:
            return jsonify({'sucesso': False, 'mensagem': 'Informe um e-mail de destino válido.'}), 400

        colab = (
            db.query(Colaborador.id, Colaborador.nome)
            .filter(Colaborador.cracha == cracha, Colaborador.ativo.is_(True))
            .first()
        )
        if not colab:
            return jsonify({'sucesso': False, 'mensagem': f'Crachá {cracha} não encontrado ou inativo.'}), 404

        if not ccs_ids:
            return jsonify({'sucesso': False, 'mensagem': 'Selecione ao menos um Centro de Custo.'}), 400

        _expirar_convites_vencidos(db, colab.id)
        ja_existe = (
            db.query(ConviteAcesso.id)
            .filter(
                ConviteAcesso.colaborador_id == colab.id,
                ConviteAcesso.status == 'DISPONIVEL'
            )
            .first()
        )
        if ja_existe:
            return jsonify({
                'sucesso': False,
                'mensagem': f'O crachá {cracha} ({colab.nome}) já possui uma hash DISPONÍVEL. Use o botão Reenviar ou Remover no Histórico.'
            }), 409

        codigo_plain = secrets.token_hex(4).upper()
        codigo_hash = hashlib.sha256(codigo_plain.encode('utf-8')).hexdigest()

        novo_convite = ConviteAcesso(
            codigo_hash=codigo_hash,
            colaborador_id=colab.id,
            email_destino=email_destino,
            status='DISPONIVEL',
            expira_em=datetime.now(timezone.utc) + timedelta(days=dias_validade),
            criado_por_id=session['usuario_id']
        )
        db.add(novo_convite)
        db.flush()

        cc_ids_unicos = [int(cc_id) for cc_id in set(ccs_ids)]
        nomes_ccs = [
            row[0]
            for row in db.query(CentroCusto.nome).filter(CentroCusto.id.in_(cc_ids_unicos)).all()
        ]

        db.bulk_save_objects([
            ConviteCentroCusto(convite_id=novo_convite.id, centro_custo_id=cc_id)
            for cc_id in cc_ids_unicos
        ])

        base_url = request.host_url.rstrip('/')
        link_primeiro_acesso = f"{base_url}/primeiro-acesso?codigo={codigo_plain}"

        notificador = NotificadorEmail()
        enviado_ok, erro_envio = notificador.enviar_convite_primeiro_acesso(
            destinatario=email_destino,
            nome_gestor=colab.nome,
            cracha=cracha,
            codigo_hash=codigo_plain,
            link_acesso=link_primeiro_acesso,
            dias_validade=dias_validade,
            centros_custo=nomes_ccs,
        )

        db.add(LogEnvioEmail(
            convite_id=novo_convite.id,
            destinatario=email_destino,
            status_envio='ENVIADO' if enviado_ok else 'ERRO',
            detalhe_erro=erro_envio,
        ))

        db.commit()

        msg_retorno = (
            f'Convite gerado e enviado para {email_destino}!'
            if enviado_ok
            else f'Hash gerada, mas falha no e-mail: {erro_envio}'
        )

        return jsonify({
            'sucesso': True,
            'email_enviado': enviado_ok,
            'erro_envio': erro_envio,
            'mensagem': msg_retorno,
            'codigo_ativacao': codigo_plain,
            'link_acesso': link_primeiro_acesso,
            'colaborador': colab.nome
        }), 201

    _expirar_convites_vencidos(db)
    db.commit()

    convites = (
        db.query(ConviteAcesso)
        .options(
            joinedload(ConviteAcesso.colaborador).load_only(Colaborador.cracha, Colaborador.nome),
            selectinload(ConviteAcesso.centros_custo)
            .joinedload(ConviteCentroCusto.centro_custo)
            .load_only(CentroCusto.nome)
        )
        .order_by(ConviteAcesso.criado_em.desc())
        .limit(80)
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


@api_bp.route('/convites/<int:convite_id>/reenviar', methods=['POST'])
def reenviar_convite_api(convite_id):
    """Regenera um novo código para o convite DISPONIVEL, atualiza a hash e reenvia o e-mail."""
    if session.get('usuario_perfil') != 'ROOT':
        return jsonify({'sucesso': False, 'mensagem': 'Acesso negado.'}), 403

    db = get_db()
    convite = (
        db.query(ConviteAcesso)
        .options(
            joinedload(ConviteAcesso.colaborador).load_only(Colaborador.cracha, Colaborador.nome),
            selectinload(ConviteAcesso.centros_custo)
            .joinedload(ConviteCentroCusto.centro_custo)
            .load_only(CentroCusto.nome)
        )
        .filter(ConviteAcesso.id == convite_id)
        .with_for_update(of=ConviteAcesso)
        .first()
    )

    if not convite:
        db.rollback()
        return jsonify({'sucesso': False, 'mensagem': 'Convite não encontrado.'}), 404

    if convite.status != 'DISPONIVEL':
        db.rollback()
        return jsonify({'sucesso': False, 'mensagem': f'Não é possível reenviar um convite com status {convite.status}.'}), 400

    novo_codigo_plain = secrets.token_hex(4).upper()
    convite.codigo_hash = hashlib.sha256(novo_codigo_plain.encode('utf-8')).hexdigest()
    convite.expira_em = datetime.now(timezone.utc) + timedelta(days=7)

    nomes_ccs = [cc.centro_custo.nome for cc in convite.centros_custo]
    base_url = request.host_url.rstrip('/')
    link_primeiro_acesso = f"{base_url}/primeiro-acesso?codigo={novo_codigo_plain}"

    notificador = NotificadorEmail()
    enviado_ok, erro_envio = notificador.enviar_convite_primeiro_acesso(
        destinatario=convite.email_destino,
        nome_gestor=convite.colaborador.nome,
        cracha=convite.colaborador.cracha,
        codigo_hash=novo_codigo_plain,
        link_acesso=link_primeiro_acesso,
        dias_validade=7,
        centros_custo=nomes_ccs,
    )

    db.add(LogEnvioEmail(
        convite_id=convite.id,
        destinatario=convite.email_destino,
        status_envio='ENVIADO' if enviado_ok else 'ERRO',
        detalhe_erro=erro_envio,
    ))

    db.commit()

    if enviado_ok:
        return jsonify({
            'sucesso': True,
            'mensagem': f'Nova hash ({novo_codigo_plain}) reenviada para {convite.email_destino}!',
            'codigo_ativacao': novo_codigo_plain
        }), 200
    else:
        return jsonify({
            'sucesso': False,
            'mensagem': f'Falha ao reenviar e-mail: {erro_envio}'
        }), 502


@api_bp.route('/convites/<int:convite_id>', methods=['DELETE'])
def remover_convite_api(convite_id):
    """Cancela/remove uma hash DISPONIVEL, liberando o crachá para novo convite."""
    if session.get('usuario_perfil') != 'ROOT':
        return jsonify({'sucesso': False, 'mensagem': 'Acesso negado.'}), 403

    db = get_db()
    convite = db.query(ConviteAcesso).filter(ConviteAcesso.id == convite_id).with_for_update().first()

    if not convite:
        db.rollback()
        return jsonify({'sucesso': False, 'mensagem': 'Convite não encontrado.'}), 404

    if convite.status == 'UTILIZADO':
        db.rollback()
        return jsonify({'sucesso': False, 'mensagem': 'Convites já utilizados não podem ser removidos.'}), 400

    db.delete(convite)
    db.commit()

    return jsonify({'sucesso': True, 'mensagem': 'Hash removida com sucesso! O crachá está liberado.'}), 200


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
            return jsonify({'sucesso': True, 'mensagem': 'Carga diária (D-1) concluída!'}), 200
    except Exception as e:
        return jsonify({'sucesso': False, 'mensagem': f'Erro ao executar ETL: {str(e)}'}), 500


@api_bp.route('/dashboard/metricas', methods=['GET'])
def dashboard_metricas():
    if session.get('usuario_perfil') != 'ROOT':
        return jsonify({'sucesso': False, 'mensagem': 'Acesso negado.'}), 403

    db = get_db()
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