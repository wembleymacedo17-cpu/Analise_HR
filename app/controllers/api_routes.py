import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from flask import Blueprint, jsonify, request, session
from sqlalchemy import func, or_
from sqlalchemy.orm import joinedload, selectinload, aliased
from werkzeug.security import check_password_hash, generate_password_hash
import json
from app import get_db
import unicodedata
from sqlalchemy.dialects.postgresql import insert as pg_insert

#---------------------------------------------------------------------------------------------------------------------
from app.models.models import (
    Colaborador, CentroCusto, Cargo, Usuario, UsuarioCentroCusto,
    ConviteAcesso, ConviteCentroCusto, OcorrenciaFalta, AnaliseFalta,
    LogEnvioEmail, HistoricoAnaliseDesfeita,
    CensoInternacaoUnidade, ProgramacaoAssistencial, RemanejamentoAssistencial,
)
#---------------------------------------------------------------------------------------------------------------------
from app.services.etl_estrutura import ETLEstruturaSenior
from app.services.etl_faltas import ETLFaltasDiario
from app.services.notificador_email import NotificadorEmail
from app.services.cookie_service import CookieService
import re
from sqlalchemy import func, or_, text
from app.services.etl_censo_local import persistir_censo_no_banco
#---------------------------------------------------------------------------------------------------------------------
from app.services.scheduler_service import (
    executar_task_faltas,
    executar_task_estrutura,
    executar_task_censo,
    iniciar_agendador_tarefa,
    parar_agendador_tarefa,
    obter_status_agendadores,
    obter_logs_terminal,
    limpar_logs_terminal,
    registrar_log,
)
#---------------------------------------------------------------------------------------------------------------------
from  app.services.queries_senior  import PALAVRAS_PROIBIDAS_SQL,LISTA_COORDENACAO, LISTA_PLANTAO_ADM
import os 




api_bp = Blueprint('api', __name__, url_prefix='/api')


def _obter_ccs_usuario(db, usuario_id: int) -> list[int]:
    rows = (
        db.query(UsuarioCentroCusto.centro_custo_id)
        .filter(UsuarioCentroCusto.usuario_id == usuario_id)
        .all()
    )
    return [r[0] for r in rows]


def _expirar_convites_vencidos(db, colaborador_id: int | None = None):
    agora = datetime.now(timezone.utc)
    q = db.query(ConviteAcesso).filter(
        ConviteAcesso.status == 'DISPONIVEL',
        ConviteAcesso.expira_em < agora
    )
    if colaborador_id is not None:
        q = q.filter(ConviteAcesso.colaborador_id == colaborador_id)
    q.update({'status': 'EXPIRADO'}, synchronize_session=False)


def _normalizar_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


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

    CookieService.iniciar_sessao_usuario(db, row)

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
    db = get_db()
    resp = jsonify({'sucesso': True, 'mensagem': 'Sessão encerrada com sucesso.'})
    CookieService.encerrar_sessao(db=db, response=resp)
    return resp, 200


@api_bp.route('/verificar-sessao', methods=['GET'])
def verificar_sessao_api():
    if 'usuario_id' not in session:
        return jsonify({'sucesso': False, 'sessao_expirada': True, 'motivo': 'expirada'}), 401

    db = get_db()
    valida, motivo, mensagem = CookieService.verificar_apenas_status(db)
    if not valida:
        return jsonify({
            'sucesso': False,
            'sessao_expirada': True,
            'motivo': motivo,
            'mensagem': mensagem,
        }), 401

    return jsonify({'sucesso': True}), 200


@api_bp.route('/primeiro-acesso', methods=['POST'])
def primeiro_acesso_api():
    data = request.json or {}
    codigo_raw = str(data.get('codigo_convite', '')).strip().upper()
    cpf = ''.join(filter(str.isdigit, str(data.get('cpf', '')))).zfill(11)
    nova_senha = str(data.get('senha', '')).strip()

    if not codigo_raw or len(cpf) != 11 or len(nova_senha) < 6:
        return jsonify({'sucesso': False, 'mensagem': 'Preencha todos os campos (senha mínima de 6 caracteres).'}), 400

    db = get_db()
    try:
        codigo_hash = hashlib.sha256(codigo_raw.encode('utf-8')).hexdigest()
        agora = datetime.now(timezone.utc)

        convite = (
            db.query(ConviteAcesso)
            .filter(ConviteAcesso.codigo_hash == codigo_hash)
            .with_for_update()
            .first()
        )

        if not convite or convite.status != 'DISPONIVEL' or _normalizar_utc(convite.expira_em) < agora:
            db.rollback()
            return jsonify({'sucesso': False, 'mensagem': 'Código de convite inválido, já utilizado ou expirado.'}), 400

        colab_cpf = (
            db.query(Colaborador.cpf)
            .filter(Colaborador.id == convite.colaborador_id)
            .scalar()
        )
        if not colab_cpf or colab_cpf.strip().zfill(11) != cpf:
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

        ccs_convite = [
            r[0] for r in db.query(ConviteCentroCusto.centro_custo_id)
            .filter(ConviteCentroCusto.convite_id == convite.id)
            .all()
        ]
        ccs_atuais = set(_obter_ccs_usuario(db, usuario.id))

        novos_vinculos = [
            UsuarioCentroCusto(usuario_id=usuario.id, centro_custo_id=cc_id)
            for cc_id in ccs_convite
            if cc_id not in ccs_atuais
        ]
        if novos_vinculos:
            db.bulk_save_objects(novos_vinculos)

        convite.status = 'UTILIZADO'
        convite.utilizado_em = agora
        db.commit()

        return jsonify({'sucesso': True, 'mensagem': 'Acesso ativado com sucesso!'}), 200

    except Exception as e:
        db.rollback()
        print(f"❌ [ERRO PRIMEIRO ACESSO] {e}")
        return jsonify({'sucesso': False, 'mensagem': f'Erro interno ao ativar acesso: {str(e)}'}), 500


@api_bp.route('/meu-perfil', methods=['GET'])
def obter_meu_perfil_api():
    id_user = session.get('usuario_id')
    if not id_user:
        return jsonify({'sucesso': False, 'mensagem': 'Não autenticado.'}), 401

    db = get_db()
    try:
        user_row = (
            db.query(
                Usuario.id,
                Usuario.role,
                Usuario.colaborador_id,
            )
            .filter(Usuario.id == int(id_user))
            .first()
        )
        if not user_row:
            return jsonify({'sucesso': False, 'mensagem': 'Usuário não encontrado.'}), 404

        colab_row = (
            db.query(
                Colaborador.nome,
                Colaborador.cracha,
                Colaborador.centro_custo_id,
            )
            .filter(Colaborador.id == user_row.colaborador_id)
            .first()
        )

        ccs_rows = (
            db.query(
                CentroCusto.id,
                CentroCusto.codigo_cc,
                CentroCusto.nome,
            )
            .join(
                UsuarioCentroCusto,
                UsuarioCentroCusto.centro_custo_id == CentroCusto.id,
            )
            .filter(
                UsuarioCentroCusto.usuario_id == int(id_user),
                CentroCusto.ativo.is_(True),
            )
            .order_by(CentroCusto.nome.asc())
            .all()
        )

        ccs_vinculados = [
            {
                'id': r.id,
                'codigo_cc': r.codigo_cc,
                'nome': r.nome,
                'label': f"{r.codigo_cc} - {r.nome}",
            }
            for r in ccs_rows
        ]

        cc_lotacao = None
        if colab_row and colab_row.centro_custo_id:
            cc_lot_row = (
                db.query(CentroCusto.codigo_cc, CentroCusto.nome)
                .filter(CentroCusto.id == colab_row.centro_custo_id)
                .first()
            )
            if cc_lot_row:
                cc_lotacao = f"{cc_lot_row.codigo_cc} - {cc_lot_row.nome}"

        return jsonify({
            'sucesso': True,
            'perfil': {
                'id': user_row.id,
                'nome': colab_row.nome if colab_row else session.get('usuario_nome'),
                'cracha': colab_row.cracha if colab_row else session.get('cracha'),
                'role': (user_row.role or 'GESTOR').upper(),
                'cc_lotacao': cc_lotacao,
                'centros_custo': ccs_vinculados,
            }
        }), 200
    except Exception as e:
        print(f"❌ [ERRO MEU PERFIL] {e}")
        return jsonify({'sucesso': False, 'mensagem': f'Erro ao buscar perfil: {str(e)}'}), 500


@api_bp.route('/meu-perfil/alterar-senha', methods=['PUT'])
def alterar_propria_senha_api():
    id_user = session.get('usuario_id')
    if not id_user:
        return jsonify({'sucesso': False, 'mensagem': 'Não autenticado.'}), 401

    data = request.json or {}
    cpf_digits = ''.join(filter(str.isdigit, str(data.get('cpf', ''))))
    senha_antiga = str(data.get('senha_antiga') or '').strip()
    nova_senha = str(data.get('nova_senha') or '').strip()
    confirmar_senha = str(data.get('confirmar_senha') or '').strip()

    if not cpf_digits or not senha_antiga or not nova_senha or not confirmar_senha:
        return jsonify({'sucesso': False, 'mensagem': 'Preencha todos os campos obrigatórios.'}), 400

    if nova_senha != confirmar_senha:
        return jsonify({'sucesso': False, 'mensagem': 'Senha não combina'}), 400

    if len(nova_senha) < 6:
        return jsonify({'sucesso': False, 'mensagem': 'A nova senha deve ter no mínimo 6 caracteres.'}), 400

    db = get_db()
    try:
        usuario_obj = (
            db.query(Usuario)
            .filter(Usuario.id == int(id_user))
            .with_for_update()
            .first()
        )
        if not usuario_obj:
            db.rollback()
            return jsonify({'sucesso': False, 'mensagem': 'Usuário não encontrado.'}), 404

        colab_row = (
            db.query(Colaborador.cpf)
            .filter(Colaborador.id == usuario_obj.colaborador_id)
            .first()
        )
        if not colab_row:
            db.rollback()
            return jsonify({'sucesso': False, 'mensagem': 'Colaborador não encontrado.'}), 404

        cpf_db_digits = ''.join(filter(str.isdigit, str(colab_row.cpf or '')))
        cpf_informado_11 = cpf_digits.zfill(11)
        cpf_db_11 = cpf_db_digits.zfill(11) if cpf_db_digits else ''

        if cpf_db_digits != cpf_digits and cpf_db_11 != cpf_informado_11:
            db.rollback()
            return jsonify({'sucesso': False, 'mensagem': 'Cpf não conforme'}), 400

        if not usuario_obj.senha_hash or not check_password_hash(usuario_obj.senha_hash, senha_antiga):
            db.rollback()
            return jsonify({'sucesso': False, 'mensagem': 'Senha não confere'}), 400

        usuario_obj.senha_hash = generate_password_hash(nova_senha)
        db.commit()

        return jsonify({'sucesso': True, 'mensagem': 'Senha alterada com sucesso!'}), 200
    except Exception as e:
        db.rollback()
        print(f"❌ [ERRO ALTERAR SENHA] {e}")
        return jsonify({'sucesso': False, 'mensagem': f'Erro ao alterar senha: {str(e)}'}), 500

# ==============================================================================
# BUSCA DE COLABORADOR PARA COBERTURA & TRANSFERÊNCIA DE CENTRO DE CUSTO
# ==============================================================================
@api_bp.route('/colaboradores/buscar', methods=['GET'])
def buscar_colaboradores_cobertura():
    if not session.get('usuario_id'):
        return jsonify({'sucesso': False, 'mensagem': 'Não autenticado.'}), 401

    termo = str(request.args.get('q', '')).strip()
    data_str = str(request.args.get('data', '')).strip()
    if len(termo) < 2:
        return jsonify({'sucesso': True, 'colaboradores': []}), 200

    db = get_db()
    filtro = (
        Colaborador.cracha.ilike(f'{termo}%')
        if termo.isdigit()
        else or_(Colaborador.nome.ilike(f'%{termo}%'), Colaborador.cracha.ilike(f'%{termo}%'))
    )

    rows = (
        db.query(
            Colaborador.id,
            Colaborador.cracha,
            Colaborador.nome,
            Colaborador.sexo,
            CentroCusto.id.label('centro_custo_id'),
            CentroCusto.codigo_cc,
            CentroCusto.nome.label('centro_custo_nome')
        )
        .join(CentroCusto, Colaborador.centro_custo_id == CentroCusto.id)
        .filter(Colaborador.ativo.is_(True), filtro)
        .order_by(Colaborador.nome.asc())
        .limit(15)
        .all()
    )

    alocacoes_map = {}
    if data_str and rows:
        try:
            data_dt = datetime.strptime(data_str, '%d/%m/%Y').date()
            colab_ids = [r.id for r in rows]
            FaltanteColab = aliased(Colaborador)

            coberturas_existentes = (
                db.query(
                    AnaliseFalta.cobridor_colaborador_id,
                    FaltanteColab.nome.label('faltante_nome'),
                    CentroCusto.nome.label('setor_falta')
                )
                .join(OcorrenciaFalta, AnaliseFalta.ocorrencia_id == OcorrenciaFalta.id)
                .join(FaltanteColab, OcorrenciaFalta.colaborador_id == FaltanteColab.id)
                .join(CentroCusto, OcorrenciaFalta.centro_custo_id == CentroCusto.id)
                .filter(
                    OcorrenciaFalta.data_ocorrencia == data_dt,
                    AnaliseFalta.cobridor_colaborador_id.in_(colab_ids)
                )
                .all()
            )
            for cob in coberturas_existentes:
                alocacoes_map.setdefault(cob.cobridor_colaborador_id, []).append({
                    'faltante_nome': cob.faltante_nome,
                    'setor_falta': cob.setor_falta
                })
        except ValueError:
            pass

    return jsonify({
        'sucesso': True,
        'colaboradores': [
            {
                'id': r.id,
                'cracha': r.cracha,
                'nome': r.nome,
                'sexo': r.sexo,
                'centro_custo_id': r.centro_custo_id,
                'codigo_cc': r.codigo_cc,
                'centro_custo': r.centro_custo_nome,
                'coberturas_no_dia': alocacoes_map.get(r.id, [])
            }
            for r in rows
        ]
    }), 200


@api_bp.route('/centros-custo/transferencia', methods=['GET'])
@api_bp.route('/meus-centros-custo', methods=['GET'])
def listar_ccs_para_transferencia():
    """Retorna todos os CCs ativos (destino) e os CCs vinculados ao usuário logado."""
    id_user = session.get('usuario_id')
    perfil = session.get('usuario_perfil')
    if not id_user:
        return jsonify({'sucesso': False, 'mensagem': 'Não autenticado.'}), 401

    db = get_db()
    todos_ccs = (
        db.query(CentroCusto.id, CentroCusto.codigo_cc, CentroCusto.nome)
        .filter(CentroCusto.ativo.is_(True))
        .order_by(CentroCusto.nome.asc())
        .all()
    )

    meus_cc_ids = [] if perfil == 'ROOT' else _obter_ccs_usuario(db, id_user)
    ccs_vinculados = (
        todos_ccs
        if perfil == 'ROOT'
        else [c for c in todos_ccs if c.id in set(meus_cc_ids)]
    )

    return jsonify({
        'sucesso': True,
        'meus_cc_ids': meus_cc_ids,
        'centros_custo': [{'id': c.id, 'codigo_cc': c.codigo_cc, 'nome': c.nome} for c in ccs_vinculados],
        'todos_centros_custo': [{'id': c.id, 'codigo_cc': c.codigo_cc, 'nome': c.nome} for c in todos_ccs]
    }), 200


@api_bp.route('/ocorrencias/buscar-externa', methods=['GET'])
@api_bp.route('/faltas/externas', methods=['GET'])
def buscar_ocorrencia_externa():
    """Permite ao gestor localizar colaboradores (com faltas pendentes/analisadas) de outros CCs para puxá-los."""
    id_user = session.get('usuario_id')
    perfil = session.get('usuario_perfil')
    if not id_user:
        return jsonify({'sucesso': False, 'mensagem': 'Não autenticado.'}), 401

    termo = str(request.args.get('q', '')).strip()
    if len(termo) < 2:
        return jsonify({'sucesso': True, 'ocorrencias': [], 'faltas': []}), 200

    db = get_db()
    filtro = (
        Colaborador.cracha.ilike(f'{termo}%')
        if termo.isdigit()
        else or_(Colaborador.nome.ilike(f'%{termo}%'), Colaborador.cracha.ilike(f'%{termo}%'))
    )

    query = (
        db.query(
            OcorrenciaFalta.id,
            OcorrenciaFalta.status,
            OcorrenciaFalta.data_ocorrencia,
            OcorrenciaFalta.centro_custo_id,
            Colaborador.id.label('colaborador_id'),
            Colaborador.cracha,
            Colaborador.nome.label('colaborador_nome'),
            Colaborador.sexo,
            Cargo.titulo.label('cargo_titulo'),
            CentroCusto.codigo_cc,
            CentroCusto.nome.label('centro_custo_nome')
        )
        .join(Colaborador, OcorrenciaFalta.colaborador_id == Colaborador.id)
        .join(CentroCusto, OcorrenciaFalta.centro_custo_id == CentroCusto.id)
        .outerjoin(Cargo, Colaborador.cargo_id == Cargo.id)
        .filter(filtro)
    )

    if perfil != 'ROOT':
        meus_ccs = _obter_ccs_usuario(db, id_user)
        if meus_ccs:
            query = query.filter(OcorrenciaFalta.centro_custo_id.notin_(meus_ccs))

    rows = query.order_by(OcorrenciaFalta.data_ocorrencia.desc()).limit(300).all()

    # 1 item por colaborador, usando a falta mais recente como referência
    agrupado = {}
    for r in rows:
        item = agrupado.get(r.colaborador_id)
        if not item:
            if len(agrupado) >= 15:
                continue
            item = agrupado[r.colaborador_id] = {
                'id': r.id,  # ocorrência de referência usada na rota mover-cc
                'colaborador_id': r.colaborador_id,
                'cracha': r.cracha,
                'colaborador_nome': r.colaborador_nome,
                'sexo': r.sexo,
                'cargo': r.cargo_titulo or '---',
                'data_ocorrencia': r.data_ocorrencia.strftime('%d/%m/%Y'),
                'centro_custo_id': r.centro_custo_id,
                'codigo_cc': r.codigo_cc,
                'centro_custo': r.centro_custo_nome,
                'qtd_faltas': 0,
                'qtd_pendentes': 0,
                'qtd_analisadas': 0,
            }
        item['qtd_faltas'] += 1
        if r.status == 'ANALISADA':
            item['qtd_analisadas'] += 1
        else:
            item['qtd_pendentes'] += 1

    itens = list(agrupado.values())

    return jsonify({
        'sucesso': True,
        'ocorrencias': itens,
        'faltas': itens
    }), 200



def _mapa_colaboradores_movimentados(db, colaborador_ids: set[int]) -> dict[int, dict]:
    """Identifica colaboradores que tiveram movimentação de Centro de Custo e guarda o CC de origem."""
    if not colaborador_ids:
        return {}
    rows = (
        db.query(
            HistoricoAnaliseDesfeita.colaborador_id,
            HistoricoAnaliseDesfeita.centro_custo_id,
            HistoricoAnaliseDesfeita.motivo,
            HistoricoAnaliseDesfeita.desfeito_em,
            CentroCusto.codigo_cc,
            CentroCusto.nome.label('cc_nome'),
        )
        .join(CentroCusto, HistoricoAnaliseDesfeita.centro_custo_id == CentroCusto.id)
        .filter(
            HistoricoAnaliseDesfeita.colaborador_id.in_(colaborador_ids),
            HistoricoAnaliseDesfeita.motivo.ilike("Transferência de Centro de Custo%"),
        )
        .order_by(HistoricoAnaliseDesfeita.desfeito_em.desc())
        .all()
    )
    mapa = {}
    for r in rows:
        if r.colaborador_id not in mapa:
            dt_fmt = (r.desfeito_em - timedelta(hours=3)).strftime('%d/%m/%Y %H:%M') if r.desfeito_em else ''
            mapa[r.colaborador_id] = {
                'detalhe': f"Origem: {r.codigo_cc} - {r.cc_nome} • {r.motivo} ({dt_fmt})",
                'cc_origem_id': r.centro_custo_id,
                'cc_origem_nome': f"{r.codigo_cc} - {r.cc_nome}",
            }
    return mapa


@api_bp.route('/faltas/<int:ocorrencia_id>/mover-cc', methods=['PUT'])
def mover_centro_custo_ocorrencia(ocorrencia_id):
    """Move o colaborador e todas as faltas dele para o novo Centro de Custo, registrando a movimentação e desfazendo análises se houver."""
    id_user = session.get('usuario_id')
    perfil = session.get('usuario_perfil')
    if not id_user:
        return jsonify({'sucesso': False, 'mensagem': 'Não autenticado.'}), 401

    data = request.json or {}
    novo_cc_id = data.get('novo_centro_custo_id') or data.get('centro_custo_id')
    atualizar_cadastro_colab = bool(data.get('atualizar_cadastro_colaborador', True))

    if not novo_cc_id:
        return jsonify({'sucesso': False, 'mensagem': 'Selecione o Centro de Custo de destino.'}), 400

    novo_cc_id = int(novo_cc_id)
    db = get_db()

    try:
        ocorrencia_ref = (
            db.query(OcorrenciaFalta)
            .filter(OcorrenciaFalta.id == ocorrencia_id)
            .with_for_update()
            .first()
        )
        if not ocorrencia_ref:
            db.rollback()
            return jsonify({'sucesso': False, 'mensagem': 'Ocorrência não encontrada.'}), 404

        cc_destino = (
            db.query(CentroCusto.id, CentroCusto.codigo_cc, CentroCusto.nome)
            .filter(CentroCusto.id == novo_cc_id, CentroCusto.ativo.is_(True))
            .first()
        )
        if not cc_destino:
            db.rollback()
            return jsonify({'sucesso': False, 'mensagem': 'Centro de Custo de destino inválido.'}), 404

        if perfil != 'ROOT':
            meus_ccs = set(_obter_ccs_usuario(db, id_user))
            origem_eh_meu = ocorrencia_ref.centro_custo_id in meus_ccs
            destino_eh_meu = novo_cc_id in meus_ccs
            if not origem_eh_meu and not destino_eh_meu:
                db.rollback()
                return jsonify({
                    'sucesso': False,
                    'mensagem': 'Você só pode transferir ocorrências saindo do seu setor ou puxando para o seu setor.'
                }), 403

        faltas_colaborador = (
            db.query(OcorrenciaFalta)
            .filter(OcorrenciaFalta.colaborador_id == ocorrencia_ref.colaborador_id)
            .with_for_update()
            .all()
        )

        colab_ref = db.query(Colaborador).filter(Colaborador.id == ocorrencia_ref.colaborador_id).first()
        if all(f.centro_custo_id == novo_cc_id for f in faltas_colaborador) and (
            not colab_ref or colab_ref.centro_custo_id == novo_cc_id
        ):
            db.rollback()
            return jsonify({'sucesso': False, 'mensagem': 'O colaborador e suas faltas já pertencem a este Centro de Custo.'}), 400

        cc_origem_id = ocorrencia_ref.centro_custo_id
        analises_desfeitas = 0
        for falta in faltas_colaborador:
            if falta.status == 'ANALISADA':
                analise_atual = (
                    db.query(AnaliseFalta)
                    .filter(AnaliseFalta.ocorrencia_id == falta.id)
                    .first()
                )
                snapshot = None
                if analise_atual:
                    snapshot = json.dumps({
                        'ausencia_programada': analise_atual.ausencia_programada,
                        'comunicada_2h_antecedencia': analise_atual.comunicada_2h_antecedencia,
                        'autorizado_hora_extra': analise_atual.autorizado_hora_extra,
                        'autorizador_he_nome': analise_atual.autorizador_he_nome,
                        'conseguiu_he_cobertura': analise_atual.conseguiu_he_cobertura,
                        'cobridor_colaborador_id': analise_atual.cobridor_colaborador_id,
                        'redividiu_equipe': analise_atual.redividiu_equipe,
                        'qtd_pacientes': analise_atual.qtd_pacientes,
                        'qtd_colaboradores': analise_atual.qtd_colaboradores,
                        'justificativa_nao_redimensionada': analise_atual.justificativa_nao_redimensionada,
                    }, default=str)

                db.add(HistoricoAnaliseDesfeita(
                    ocorrencia_id=falta.id,
                    colaborador_id=falta.colaborador_id,
                    centro_custo_id=falta.centro_custo_id,
                    data_ocorrencia=falta.data_ocorrencia,
                    desfeito_por_id=id_user,
                    motivo=f"Transferência de Centro de Custo para {cc_destino.codigo_cc} - {cc_destino.nome}",
                    dados_analise_anterior=snapshot,
                ))
                db.query(AnaliseFalta).filter(AnaliseFalta.ocorrencia_id == falta.id).delete(synchronize_session=False)
                falta.status = 'PENDENTE'
                analises_desfeitas += 1

            falta.centro_custo_id = novo_cc_id

        # Garante registro da movimentação no histórico mesmo quando as faltas estavam pendentes
        if analises_desfeitas == 0:
            db.add(HistoricoAnaliseDesfeita(
                ocorrencia_id=ocorrencia_ref.id,
                colaborador_id=ocorrencia_ref.colaborador_id,
                centro_custo_id=cc_origem_id,
                data_ocorrencia=ocorrencia_ref.data_ocorrencia,
                desfeito_por_id=id_user,
                motivo=f"Transferência de Centro de Custo para {cc_destino.codigo_cc} - {cc_destino.nome}",
                dados_analise_anterior=None,
            ))

        if atualizar_cadastro_colab and colab_ref:
            colab_ref.centro_custo_id = novo_cc_id

        db.commit()

        extra_msg = (
            f" ({analises_desfeitas} análise(s) desfeita(s) e retornada(s) para Pendente)"
            if analises_desfeitas > 0
            else ""
        )
        return jsonify({
            'sucesso': True,
            'mensagem': f'{len(faltas_colaborador)} ocorrência(s) transferida(s) para {cc_destino.codigo_cc} - {cc_destino.nome}!{extra_msg}'
        }), 200

    except Exception as e:
        db.rollback()
        return jsonify({'sucesso': False, 'mensagem': f'Erro ao mover Centro de Custo: {str(e)}'}), 500


@api_bp.route('/faltas/<int:ocorrencia_id>/devolver-cc', methods=['POST'])
def devolver_centro_custo_ocorrencia(ocorrencia_id):
    """Devolve o colaborador movimentado ao Centro de Custo de origem e desfaz todas as análises vinculadas a ele."""
    id_user = session.get('usuario_id')
    if not id_user:
        return jsonify({'sucesso': False, 'mensagem': 'Não autenticado.'}), 401

    db = get_db()
    try:
        ocorrencia_ref = (
            db.query(OcorrenciaFalta)
            .filter(OcorrenciaFalta.id == ocorrencia_id)
            .with_for_update()
            .first()
        )
        if not ocorrencia_ref:
            db.rollback()
            return jsonify({'sucesso': False, 'mensagem': 'Ocorrência não encontrada.'}), 404

        ultima_transf = (
            db.query(
                HistoricoAnaliseDesfeita.centro_custo_id,
                CentroCusto.codigo_cc,
                CentroCusto.nome.label('cc_nome'),
            )
            .join(CentroCusto, HistoricoAnaliseDesfeita.centro_custo_id == CentroCusto.id)
            .filter(
                HistoricoAnaliseDesfeita.colaborador_id == ocorrencia_ref.colaborador_id,
                HistoricoAnaliseDesfeita.motivo.ilike("Transferência de Centro de Custo%"),
            )
            .order_by(HistoricoAnaliseDesfeita.desfeito_em.desc())
            .first()
        )

        if not ultima_transf:
            db.rollback()
            return jsonify({'sucesso': False, 'mensagem': 'Não foi encontrado um setor de origem registrado para devolução.'}), 400

        cc_origem_id = ultima_transf.centro_custo_id
        if cc_origem_id == ocorrencia_ref.centro_custo_id:
            db.rollback()
            return jsonify({'sucesso': False, 'mensagem': 'O colaborador já se encontra no Centro de Custo de origem.'}), 400

        faltas_colaborador = (
            db.query(OcorrenciaFalta)
            .filter(OcorrenciaFalta.colaborador_id == ocorrencia_ref.colaborador_id)
            .with_for_update()
            .all()
        )

        analises_desfeitas = 0
        for falta in faltas_colaborador:
            snapshot = None
            if falta.status == 'ANALISADA':
                analise_atual = db.query(AnaliseFalta).filter(AnaliseFalta.ocorrencia_id == falta.id).first()
                if analise_atual:
                    snapshot = json.dumps({
                        'ausencia_programada': analise_atual.ausencia_programada,
                        'comunicada_2h_antecedencia': analise_atual.comunicada_2h_antecedencia,
                        'autorizado_hora_extra': analise_atual.autorizado_hora_extra,
                        'autorizador_he_nome': analise_atual.autorizador_he_nome,
                        'conseguiu_he_cobertura': analise_atual.conseguiu_he_cobertura,
                        'cobridor_colaborador_id': analise_atual.cobridor_colaborador_id,
                        'redividiu_equipe': analise_atual.redividiu_equipe,
                        'qtd_pacientes': analise_atual.qtd_pacientes,
                        'qtd_colaboradores': analise_atual.qtd_colaboradores,
                        'justificativa_nao_redimensionada': analise_atual.justificativa_nao_redimensionada,
                    }, default=str)

                db.query(AnaliseFalta).filter(AnaliseFalta.ocorrencia_id == falta.id).delete(synchronize_session=False)
                falta.status = 'PENDENTE'
                analises_desfeitas += 1

            db.add(HistoricoAnaliseDesfeita(
                ocorrencia_id=falta.id,
                colaborador_id=falta.colaborador_id,
                centro_custo_id=falta.centro_custo_id,
                data_ocorrencia=falta.data_ocorrencia,
                desfeito_por_id=id_user,
                motivo=f"Devolução de Centro de Custo para {ultima_transf.codigo_cc} - {ultima_transf.cc_nome}",
                dados_analise_anterior=snapshot,
            ))
            falta.centro_custo_id = cc_origem_id

        colab_ref = db.query(Colaborador).filter(Colaborador.id == ocorrencia_ref.colaborador_id).first()
        if colab_ref:
            colab_ref.centro_custo_id = cc_origem_id

        db.commit()

        extra_msg = f" e {analises_desfeitas} análise(s) desfeita(s)" if analises_desfeitas > 0 else ""
        return jsonify({
            'sucesso': True,
            'mensagem': f'Colaborador devolvido para {ultima_transf.codigo_cc} - {ultima_transf.cc_nome} ({len(faltas_colaborador)} ocorrência(s) restaurada(s){extra_msg})!'
        }), 200

    except Exception as e:
        db.rollback()
        return jsonify({'sucesso': False, 'mensagem': f'Erro ao devolver Centro de Custo: {str(e)}'}), 500

@api_bp.route('/faltas', methods=['GET'])
def listar_faltas():
    id_user = session.get('usuario_id')
    perfil = session.get('usuario_perfil')
    if not id_user:
        return jsonify({'sucesso': False, 'mensagem': 'Não autenticado.'}), 401

    db = get_db()
    status_filtro = str(request.args.get('status', 'PENDENTE')).strip().upper()
    if status_filtro not in ('PENDENTE', 'ANALISADA'):
        status_filtro = 'PENDENTE'

    cc_ids = None
    if perfil != 'ROOT':
        cc_ids = _obter_ccs_usuario(db, id_user)
        if not cc_ids:
            return jsonify({
                'sucesso': True,
                'usuario_id': id_user,
                'faltas': [],
                'kpis_gestor': {'pendentes': 0, 'analisadas': 0}
            }), 200

    kpi_q = db.query(OcorrenciaFalta.status, func.count(OcorrenciaFalta.id))
    if cc_ids is not None:
        kpi_q = kpi_q.filter(OcorrenciaFalta.centro_custo_id.in_(cc_ids))
    kpi_map = dict(kpi_q.group_by(OcorrenciaFalta.status).all())

    query = (
        db.query(
            OcorrenciaFalta.id,
            OcorrenciaFalta.colaborador_id,
            OcorrenciaFalta.centro_custo_id,
            OcorrenciaFalta.data_ocorrencia,
            OcorrenciaFalta.status,
            Colaborador.cracha,
            Colaborador.nome.label('colaborador_nome'),
            Colaborador.sexo,
            Cargo.titulo.label('cargo_titulo'),
            CentroCusto.codigo_cc,
            CentroCusto.nome.label('centro_custo_nome')
        )
        .join(Colaborador, OcorrenciaFalta.colaborador_id == Colaborador.id)
        .join(CentroCusto, OcorrenciaFalta.centro_custo_id == CentroCusto.id)
        .outerjoin(Cargo, Colaborador.cargo_id == Cargo.id)
        .filter(OcorrenciaFalta.status == status_filtro)
    )

    if cc_ids is not None:
        query = query.filter(OcorrenciaFalta.centro_custo_id.in_(cc_ids))

    rows = query.order_by(OcorrenciaFalta.data_ocorrencia.desc()).limit(300).all()

    analises_map = {}
    if status_filtro == 'ANALISADA' and rows:
        ocorr_ids = [r.id for r in rows]
        AvaliadorColab = aliased(Colaborador)
        CobridorColab = aliased(Colaborador)
        CobridorCC = aliased(CentroCusto)

        analises_rows = (
            db.query(
                AnaliseFalta.ocorrencia_id,
                AnaliseFalta.ausencia_programada,
                AnaliseFalta.comunicada_2h_antecedencia,
                AnaliseFalta.foi_troca_folga,
                AnaliseFalta.autorizado_hora_extra,
                AnaliseFalta.autorizador_he_nome,
                AnaliseFalta.conseguiu_he_cobertura,
                AnaliseFalta.redividiu_equipe,
                AnaliseFalta.qtd_pacientes,
                AnaliseFalta.qtd_colaboradores,
                AnaliseFalta.justificativa_nao_redimensionada,
                AnaliseFalta.respondido_em,
                AvaliadorColab.nome.label('avaliador_nome'),
                CobridorColab.cracha.label('cobridor_cracha'),
                CobridorColab.nome.label('cobridor_nome'),
                CobridorCC.codigo_cc.label('cobridor_codigo_cc'),
                CobridorCC.nome.label('cobridor_cc_nome')
            )
            .join(Usuario, AnaliseFalta.avaliador_id == Usuario.id)
            .join(AvaliadorColab, Usuario.colaborador_id == AvaliadorColab.id)
            .outerjoin(CobridorColab, AnaliseFalta.cobridor_colaborador_id == CobridorColab.id)
            .outerjoin(CobridorCC, AnaliseFalta.cobridor_centro_custo_id == CobridorCC.id)
            .filter(AnaliseFalta.ocorrencia_id.in_(ocorr_ids))
            .all()
        )
        for a in analises_rows:
            dt_resp = (a.respondido_em - timedelta(hours=3)).strftime('%d/%m/%Y %H:%M') if a.respondido_em else ''
            analises_map[a.ocorrencia_id] = {
                'ausencia_programada': a.ausencia_programada,
                'comunicada_2h_antecedencia': a.comunicada_2h_antecedencia,
                'foi_troca_folga': a.foi_troca_folga,
                'autorizado_hora_extra': a.autorizado_hora_extra,
                'autorizador_he_nome': a.autorizador_he_nome,
                'conseguiu_he_cobertura': a.conseguiu_he_cobertura,
                'redividiu_equipe': a.redividiu_equipe,
                'qtd_pacientes': a.qtd_pacientes,
                'qtd_colaboradores': a.qtd_colaboradores,
                'justificativa_nao_redimensionada': a.justificativa_nao_redimensionada,
                'cobridor': (
                    f"{a.cobridor_cracha} - {a.cobridor_nome} ({a.cobridor_codigo_cc} - {a.cobridor_cc_nome})"
                    if a.cobridor_nome else None
                ),
                'avaliador': a.avaliador_nome,
                'respondido_em': dt_resp
            }

    colab_ids = {r.colaborador_id for r in rows}
    movimentados_map = _mapa_colaboradores_movimentados(db, colab_ids)

    lista = []
    for r in rows:
        mov_obj = movimentados_map.get(r.colaborador_id)
        foi_movimentado = bool(mov_obj and mov_obj['cc_origem_id'] != r.centro_custo_id)
        lista.append({
            'id': r.id,
            'colaborador_id': r.colaborador_id,
            'centro_custo_id': r.centro_custo_id,
            'cracha': r.cracha,
            'colaborador_nome': r.colaborador_nome,
            'sexo': r.sexo,
            'cargo': r.cargo_titulo or '---',
            'codigo_cc': r.codigo_cc,
            'centro_custo': r.centro_custo_nome,
            'data_ocorrencia': r.data_ocorrencia.strftime('%d/%m/%Y'),
            'status': r.status,
            'movimentado_cc': foi_movimentado,
            'movimentado_detalhe': mov_obj['detalhe'] if foi_movimentado else None,
            'cc_origem_nome': mov_obj['cc_origem_nome'] if foi_movimentado else None,
            'analise': analises_map.get(r.id)
        })

    return jsonify({
        'sucesso': True,
        'usuario_id': id_user,
        'faltas': lista,
        'kpis_gestor': {
            'pendentes': kpi_map.get('PENDENTE', 0),
            'analisadas': kpi_map.get('ANALISADA', 0)
        }
    }), 200

def _normalizar_nome_lista(texto: str) -> str:
    return unicodedata.normalize('NFC', str(texto or '')).strip()


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

    ausencia_programada = bool(data.get('ausencia_programada'))

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

    if ausencia_programada:
        nova_analise = AnaliseFalta(
            ocorrencia_id=ocorrencia.id,
            avaliador_id=id_user,
            ausencia_programada=True,
            comunicada_2h_antecedencia=None,
            foi_troca_folga=None,
            autorizado_hora_extra=None,
            autorizador_he_nome=None,
            conseguiu_he_cobertura=None,
            cobridor_colaborador_id=None,
            cobridor_centro_custo_id=None,
            redividiu_equipe=None,
            qtd_pacientes=None,
            qtd_colaboradores=None,
            justificativa_nao_redimensionada=None
        )
        ocorrencia.status = 'ANALISADA'
        db.add(nova_analise)
        db.commit()
        return jsonify({'sucesso': True, 'mensagem': 'Ausência programada registrada com sucesso!'}), 200

    comunicada_2h = bool(data.get('comunicada_2h_antecedencia'))
    autorizado_he = bool(data.get('autorizado_hora_extra'))
    tipo_autorizador_he = str(data.get('tipo_autorizador_he') or '').strip().upper() or None
    autorizador_he_nome = str(data.get('autorizador_he_nome') or '').strip() or None
    conseguiu_he = bool(data.get('conseguiu_he_cobertura')) if autorizado_he else False
    cobridor_id_raw = data.get('cobridor_colaborador_id')

    if autorizado_he:
        autorizador_he_norm = _normalizar_nome_lista(autorizador_he_nome)
        permitidos_norm = {
            _normalizar_nome_lista(nome).upper(): nome
            for nome in (set(LISTA_PLANTAO_ADM) | set(LISTA_COORDENACAO))
        }
        chave_busca = autorizador_he_norm.upper()
        if not chave_busca or chave_busca not in permitidos_norm:
            db.rollback()
            return jsonify({
                'sucesso': False,
                'mensagem': f'Responsável inválido ({autorizador_he_norm or "vazio"}). Volte à Etapa 3 e selecione um nome.'
            }), 400

        nome_canonico = permitidos_norm[chave_busca]
        if tipo_autorizador_he == 'PLANTAO_ADM':
            autorizador_he_nome_salvo = f"[Plantão Adm] {nome_canonico}"
        elif tipo_autorizador_he == 'COORDENACAO':
            autorizador_he_nome_salvo = f"[GER/COORD/SUP] {nome_canonico}"
        else:
            autorizador_he_nome_salvo = nome_canonico
    else:
        autorizador_he_nome_salvo = None

    cobridor_id = None
    cobridor_cc_id = None
    redividiu = None
    qtd_pacientes = None
    qtd_colaboradores = None
    justificativa_texto = None

    if autorizado_he and conseguiu_he:
        if not cobridor_id_raw:
            db.rollback()
            return jsonify({'sucesso': False, 'mensagem': 'Informe o crachá/nome de quem cobriu a ausência.'}), 400

        cobridor_row = (
            db.query(Colaborador.id, Colaborador.cracha, Colaborador.nome, Colaborador.centro_custo_id)
            .filter(Colaborador.id == int(cobridor_id_raw), Colaborador.ativo.is_(True))
            .with_for_update()
            .first()
        )
        if not cobridor_row:
            db.rollback()
            return jsonify({'sucesso': False, 'mensagem': 'Colaborador selecionado para cobertura não encontrado.'}), 400

        if cobridor_row.id == ocorrencia.colaborador_id:
            db.rollback()
            return jsonify({'sucesso': False, 'mensagem': 'O colaborador faltante não pode cobrir a própria falta.'}), 400

        FaltanteExistente = aliased(Colaborador)
        conflito = (
            db.query(
                AnaliseFalta.id,
                FaltanteExistente.nome.label('faltante_nome'),
                CentroCusto.nome.label('setor_nome')
            )
            .join(OcorrenciaFalta, AnaliseFalta.ocorrencia_id == OcorrenciaFalta.id)
            .join(FaltanteExistente, OcorrenciaFalta.colaborador_id == FaltanteExistente.id)
            .join(CentroCusto, OcorrenciaFalta.centro_custo_id == CentroCusto.id)
            .filter(
                AnaliseFalta.cobridor_colaborador_id == cobridor_row.id,
                OcorrenciaFalta.data_ocorrencia == ocorrencia.data_ocorrencia,
                OcorrenciaFalta.id != ocorrencia.id
            )
            .first()
        )
        if conflito:
            db.rollback()
            data_fmt = ocorrencia.data_ocorrencia.strftime('%d/%m/%Y')
            return jsonify({
                'sucesso': False,
                'mensagem': (
                    f'Conflito de escala: {cobridor_row.nome} (Crachá {cobridor_row.cracha}) já está cobrindo '
                    f'{conflito.faltante_nome} no setor {conflito.setor_nome} em {data_fmt}.'
                )
            }), 409

        cobridor_id = cobridor_row.id
        cobridor_cc_id = cobridor_row.centro_custo_id
        redividiu = False

    else:
        if data.get('redividiu_equipe') is None:
            db.rollback()
            return jsonify({'sucesso': False, 'mensagem': 'Informe a adequação da equipe.'}), 400

        redividiu = bool(data.get('redividiu_equipe'))

        if redividiu:
            try:
                qtd_pacientes = int(data.get('qtd_pacientes'))
                qtd_colaboradores = int(data.get('qtd_colaboradores'))
            except (TypeError, ValueError):
                db.rollback()
                return jsonify({
                    'sucesso': False,
                    'mensagem': 'Informe o número de pacientes e o número de colaboradores.'
                }), 400

            if qtd_pacientes < 1 or qtd_colaboradores < 1:
                db.rollback()
                return jsonify({
                    'sucesso': False,
                    'mensagem': 'O número de pacientes e de colaboradores devem ser maiores que zero.'
                }), 400
        else:
            remanejamentos_setores = data.get('remanejamentos_setores') or []
            itens_validos = []

            for item in remanejamentos_setores:
                try:
                    cc_id_item = int(item.get('cc_id') or 0)
                    qtd_item = int(item.get('qtd') or 0)
                except (TypeError, ValueError):
                    continue
                if cc_id_item > 0 and qtd_item > 0:
                    itens_validos.append((cc_id_item, qtd_item))

            if itens_validos:
                cc_ids_req = [cc_id for cc_id, _ in itens_validos]
                ccs_db = {
                    row.id: f"{row.codigo_cc} - {row.nome}"
                    for row in db.query(CentroCusto.id, CentroCusto.codigo_cc, CentroCusto.nome)
                    .filter(CentroCusto.id.in_(cc_ids_req), CentroCusto.ativo.is_(True))
                    .all()
                }
                if len(ccs_db) != len(set(cc_ids_req)):
                    db.rollback()
                    return jsonify({'sucesso': False, 'mensagem': 'Um ou mais Centros de Custo informados são inválidos.'}), 400

                qtd_colaboradores = sum(qtd for _, qtd in itens_validos)
                cobridor_cc_id = itens_validos[0][0]
                partes_desc = [f"{qtd} colab. de {ccs_db[cc_id]}" for cc_id, qtd in itens_validos]
                justificativa_texto = f"Remanejamento entre setores ({qtd_colaboradores} colab.): {'; '.join(partes_desc)}"
            else:
                try:
                    qtd_colaboradores = int(data.get('qtd_colaboradores') or 0)
                except (TypeError, ValueError):
                    qtd_colaboradores = 0

                cc_origem_rem_id = data.get('cc_origem_remanejamento_id')
                justificativa_texto = str(data.get('justificativa_nao_redimensionada') or '').strip()

                if qtd_colaboradores < 1 or not cc_origem_rem_id or not justificativa_texto:
                    db.rollback()
                    return jsonify({
                        'sucesso': False,
                        'mensagem': 'Adicione pelo menos um Centro de Custo de origem e a quantidade de colaboradores.'
                    }), 400

                cc_origem_existe = (
                    db.query(CentroCusto.id)
                    .filter(CentroCusto.id == int(cc_origem_rem_id), CentroCusto.ativo.is_(True))
                    .first()
                )
                if not cc_origem_existe:
                    db.rollback()
                    return jsonify({'sucesso': False, 'mensagem': 'Centro de Custo de origem inválido.'}), 400

                cobridor_cc_id = int(cc_origem_rem_id)

    nova_analise = AnaliseFalta(
        ocorrencia_id=ocorrencia.id,
        avaliador_id=id_user,
        ausencia_programada=False,
        comunicada_2h_antecedencia=comunicada_2h,
        foi_troca_folga=False,
        autorizado_hora_extra=autorizado_he,
        autorizador_he_nome=autorizador_he_nome_salvo,
        conseguiu_he_cobertura=conseguiu_he,
        cobridor_colaborador_id=cobridor_id,
        cobridor_centro_custo_id=cobridor_cc_id,
        redividiu_equipe=redividiu,
        qtd_pacientes=qtd_pacientes,
        qtd_colaboradores=qtd_colaboradores,
        justificativa_nao_redimensionada=justificativa_texto
    )
    ocorrencia.status = 'ANALISADA'
    db.add(nova_analise)
    db.commit()

    return jsonify({'sucesso': True, 'mensagem': 'Análise registrada com sucesso!'}), 200
# ADMINISTRAÇÃO ROOT (VALIDAÇÃO CRACHÁ, CONVITES, GESTORES, ETL E MÉTRICAS)
# ==============================================================================
@api_bp.route('/colaboradores/<string:cracha>', methods=['GET'])
def validar_cracha_colaborador(cracha):
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

    usuario_existente = (
        db.query(Usuario.id, Usuario.role, Usuario.ativo)
        .filter(Usuario.colaborador_id == row.id)
        .first()
    )
    if usuario_existente:
        status_txt = "ATIVO" if usuario_existente.ativo else "BLOQUEADO"
        return jsonify({
            'sucesso': False,
            'usuario_existente': True,
            'mensagem': (
                f'O crachá {cracha_limpo} ({row.nome}) já possui acesso liberado '
                f'(Perfil: {usuario_existente.role} • {status_txt}). '
                f'Para alterar setores ou senha, utilize a aba Gestão de Perfis.'
            )
        }), 409

    _expirar_convites_vencidos(db, row.id)
    db.commit()

    convite_ativo = (
        db.query(ConviteAcesso.id)
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



@api_bp.route('/visao-global/gestores', methods=['GET'])
def visao_global_gestores():
    """Retorna para o ROOT os gestores com contagem de análises feitas e pendentes, e as ocorrências de cada gestor."""
    if session.get('usuario_perfil') != 'ROOT':
        return jsonify({'sucesso': False, 'mensagem': 'Acesso negado.'}), 403

    db = get_db()

    usuarios = (
        db.query(Usuario)
        .options(
            joinedload(Usuario.colaborador).load_only(Colaborador.cracha, Colaborador.nome),
            selectinload(Usuario.centros_custo)
            .joinedload(UsuarioCentroCusto.centro_custo)
            .load_only(CentroCusto.id, CentroCusto.codigo_cc, CentroCusto.nome)
        )
        .filter(Usuario.role == 'GESTOR', Usuario.ativo.is_(True))
        .order_by(Usuario.id.asc())
        .all()
    )

    todos_cc_ids = {
        uc.centro_custo_id
        for u in usuarios
        for uc in u.centros_custo
    }

    ocorrencias_por_cc = {cc_id: [] for cc_id in todos_cc_ids}

    if todos_cc_ids:
        AvaliadorColab = aliased(Colaborador)
        CobridorColab = aliased(Colaborador)
        CobridorCC = aliased(CentroCusto)

        rows = (
            db.query(
                OcorrenciaFalta.id,
                OcorrenciaFalta.colaborador_id,
                OcorrenciaFalta.centro_custo_id,
                OcorrenciaFalta.data_ocorrencia,
                OcorrenciaFalta.status,
                Colaborador.cracha,
                Colaborador.nome.label('colaborador_nome'),
                Colaborador.sexo,
                Cargo.titulo.label('cargo_titulo'),
                CentroCusto.codigo_cc,
                CentroCusto.nome.label('centro_custo_nome'),
                AnaliseFalta.ausencia_programada,
                AnaliseFalta.comunicada_2h_antecedencia,
                AnaliseFalta.autorizado_hora_extra,
                AnaliseFalta.autorizador_he_nome,
                AnaliseFalta.conseguiu_he_cobertura,
                AnaliseFalta.redividiu_equipe,
                AnaliseFalta.qtd_pacientes,
                AnaliseFalta.qtd_colaboradores,
                AnaliseFalta.justificativa_nao_redimensionada,
                AnaliseFalta.respondido_em,
                AvaliadorColab.nome.label('avaliador_nome'),
                CobridorColab.cracha.label('cobridor_cracha'),
                CobridorColab.nome.label('cobridor_nome'),
                CobridorCC.codigo_cc.label('cobridor_codigo_cc'),
                CobridorCC.nome.label('cobridor_cc_nome')
            )
            .join(Colaborador, OcorrenciaFalta.colaborador_id == Colaborador.id)
            .join(CentroCusto, OcorrenciaFalta.centro_custo_id == CentroCusto.id)
            .outerjoin(Cargo, Colaborador.cargo_id == Cargo.id)
            .outerjoin(AnaliseFalta, AnaliseFalta.ocorrencia_id == OcorrenciaFalta.id)
            .outerjoin(Usuario, AnaliseFalta.avaliador_id == Usuario.id)
            .outerjoin(AvaliadorColab, Usuario.colaborador_id == AvaliadorColab.id)
            .outerjoin(CobridorColab, AnaliseFalta.cobridor_colaborador_id == CobridorColab.id)
            .outerjoin(CobridorCC, AnaliseFalta.cobridor_centro_custo_id == CobridorCC.id)
            .filter(OcorrenciaFalta.centro_custo_id.in_(todos_cc_ids))
            .order_by(OcorrenciaFalta.data_ocorrencia.desc())
            .all()
        )

        colab_ids = {r.colaborador_id for r in rows}
        movimentados_map = _mapa_colaboradores_movimentados(db, colab_ids)

        for r in rows:
            analise_obj = None
            if r.status == 'ANALISADA' and r.avaliador_nome:
                dt_resp = (r.respondido_em - timedelta(hours=3)).strftime('%d/%m/%Y %H:%M') if r.respondido_em else ''
                analise_obj = {
                    'ausencia_programada': r.ausencia_programada,
                    'comunicada_2h_antecedencia': r.comunicada_2h_antecedencia,
                    'autorizado_hora_extra': r.autorizado_hora_extra,
                    'autorizador_he_nome': r.autorizador_he_nome,
                    'conseguiu_he_cobertura': r.conseguiu_he_cobertura,
                    'redividiu_equipe': r.redividiu_equipe,
                    'qtd_pacientes': r.qtd_pacientes,
                    'qtd_colaboradores': r.qtd_colaboradores,
                    'justificativa_nao_redimensionada': r.justificativa_nao_redimensionada,
                    'cobridor': (
                        f"{r.cobridor_cracha} - {r.cobridor_nome} ({r.cobridor_codigo_cc} - {r.cobridor_cc_nome})"
                        if r.cobridor_nome else None
                    ),
                    'avaliador': r.avaliador_nome,
                    'respondido_em': dt_resp
                }

            mov_obj = movimentados_map.get(r.colaborador_id)
            foi_movimentado = bool(mov_obj and mov_obj['cc_origem_id'] != r.centro_custo_id)
            ocorrencias_por_cc.setdefault(r.centro_custo_id, []).append({
                'id': r.id,
                'colaborador_id': r.colaborador_id,
                'centro_custo_id': r.centro_custo_id,
                'cracha': r.cracha,
                'colaborador_nome': r.colaborador_nome,
                'sexo': r.sexo,
                'cargo': r.cargo_titulo or '---',
                'codigo_cc': r.codigo_cc,
                'centro_custo': r.centro_custo_nome,
                'data_ocorrencia': r.data_ocorrencia.strftime('%d/%m/%Y'),
                'status': r.status,
                'movimentado_cc': foi_movimentado,
                'movimentado_detalhe': mov_obj['detalhe'] if foi_movimentado else None,
                'cc_origem_nome': mov_obj['cc_origem_nome'] if foi_movimentado else None,
                'analise': analise_obj
            })

    gestores_payload = []
    for u in usuarios:
        cc_ids_u = [uc.centro_custo_id for uc in u.centros_custo]
        ccs_nomes_u = [f"{uc.centro_custo.codigo_cc} - {uc.centro_custo.nome}" for uc in u.centros_custo]

        vistas = set()
        ocorr_gestor = []
        for cc_id in cc_ids_u:
            for oc in ocorrencias_por_cc.get(cc_id, []):
                if oc['id'] not in vistas:
                    vistas.add(oc['id'])
                    ocorr_gestor.append(oc)

        qtd_analisadas = sum(1 for oc in ocorr_gestor if oc['status'] == 'ANALISADA')
        qtd_pendentes = sum(1 for oc in ocorr_gestor if oc['status'] == 'PENDENTE')

        gestores_payload.append({
            'id': u.id,
            'cracha': u.colaborador.cracha,
            'nome': u.colaborador.nome,
            'centros_custo': ccs_nomes_u,
            'analises_feitas': qtd_analisadas,
            'pendentes': qtd_pendentes,
            'ocorrencias': ocorr_gestor
        })

    return jsonify({
        'sucesso': True,
        'gestores': gestores_payload
    }), 200


@api_bp.route('/visao-global/gestores/<int:usuario_id>/historico', methods=['GET'])
def historico_movimentacoes_gestor(usuario_id):
    """
    Retorna todas as movimentações ocorridas nos Centros de Custo do gestor
    (incluindo ações feitas pelo próprio gestor ou por outro perfil como ROOT).
    Acessível pelo ROOT ou pelo próprio GESTOR.
    """
    id_logado = session.get('usuario_id')
    perfil_logado = session.get('usuario_perfil')
    if not id_logado:
        return jsonify({'sucesso': False, 'mensagem': 'Não autenticado.'}), 401

    if perfil_logado != 'ROOT' and int(id_logado) != int(usuario_id):
        return jsonify({'sucesso': False, 'mensagem': 'Acesso negado.'}), 403

    db = get_db()
    user = (
        db.query(Usuario)
        .options(
            joinedload(Usuario.colaborador).load_only(Colaborador.cracha, Colaborador.nome),
            selectinload(Usuario.centros_custo)
        )
        .filter(Usuario.id == usuario_id)
        .first()
    )
    if not user:
        return jsonify({'sucesso': False, 'mensagem': 'Perfil não encontrado.'}), 404

    ccs_gestor = [uc.centro_custo_id for uc in user.centros_custo]
    eventos = []

    # 1. Análises registradas nos CCs do gestor OU feitas diretamente por ele
    AutorUser = aliased(Usuario)
    AutorColab = aliased(Colaborador)

    q_analises = (
        db.query(
            AnaliseFalta.id,
            AnaliseFalta.avaliador_id,
            AnaliseFalta.respondido_em,
            AnaliseFalta.ausencia_programada,
            AnaliseFalta.autorizado_hora_extra,
            AnaliseFalta.conseguiu_he_cobertura,
            AnaliseFalta.redividiu_equipe,
            OcorrenciaFalta.data_ocorrencia,
            Colaborador.cracha,
            Colaborador.nome.label('colab_nome'),
            CentroCusto.codigo_cc,
            CentroCusto.nome.label('cc_nome'),
            AutorUser.role.label('autor_role'),
            AutorColab.nome.label('autor_nome'),
        )
        .join(OcorrenciaFalta, AnaliseFalta.ocorrencia_id == OcorrenciaFalta.id)
        .join(Colaborador, OcorrenciaFalta.colaborador_id == Colaborador.id)
        .join(CentroCusto, OcorrenciaFalta.centro_custo_id == CentroCusto.id)
        .join(AutorUser, AnaliseFalta.avaliador_id == AutorUser.id)
        .join(AutorColab, AutorUser.colaborador_id == AutorColab.id)
    )
    if ccs_gestor:
        q_analises = q_analises.filter(
            or_(
                OcorrenciaFalta.centro_custo_id.in_(ccs_gestor),
                AnaliseFalta.avaliador_id == usuario_id,
            )
        )
    else:
        q_analises = q_analises.filter(AnaliseFalta.avaliador_id == usuario_id)

    for a in q_analises.order_by(AnaliseFalta.respondido_em.desc()).limit(200).all():
        if a.ausencia_programada:
            resumo = "Ausência programada"
        elif a.autorizado_hora_extra and a.conseguiu_he_cobertura:
            resumo = "Cobertura com Hora Extra"
        elif a.redividiu_equipe:
            resumo = "Equipe redimensionada"
        else:
            resumo = "Sem redimensionamento (justificado)"

        outro_perfil = int(a.avaliador_id) != int(usuario_id)
        eventos.append({
            'ts': a.respondido_em.isoformat() if a.respondido_em else '',
            'data_hora': (a.respondido_em - timedelta(hours=3)).strftime('%d/%m/%Y %H:%M') if a.respondido_em else '--',
            'tipo': 'ANALISE',
            'tipo_label': 'Análise Registrada',
            'colaborador': f"{a.cracha} - {a.colab_nome}",
            'data_falta': a.data_ocorrencia.strftime('%d/%m/%Y') if a.data_ocorrencia else '--',
            'setor': f"{a.codigo_cc} - {a.cc_nome}",
            'detalhe': resumo,
            'executado_por': f"{a.autor_nome} ({a.autor_role})",
            'outro_perfil': outro_perfil,
        })

    # 2. Análises desfeitas, transferências e devoluções de CC
    q_hist = (
        db.query(
            HistoricoAnaliseDesfeita.id,
            HistoricoAnaliseDesfeita.desfeito_por_id,
            HistoricoAnaliseDesfeita.desfeito_em,
            HistoricoAnaliseDesfeita.data_ocorrencia,
            HistoricoAnaliseDesfeita.motivo,
            Colaborador.cracha,
            Colaborador.nome.label('colab_nome'),
            CentroCusto.codigo_cc,
            CentroCusto.nome.label('cc_nome'),
            AutorUser.role.label('autor_role'),
            AutorColab.nome.label('autor_nome'),
        )
        .join(Colaborador, HistoricoAnaliseDesfeita.colaborador_id == Colaborador.id)
        .join(CentroCusto, HistoricoAnaliseDesfeita.centro_custo_id == CentroCusto.id)
        .join(AutorUser, HistoricoAnaliseDesfeita.desfeito_por_id == AutorUser.id)
        .join(AutorColab, AutorUser.colaborador_id == AutorColab.id)
    )
    if ccs_gestor:
        q_hist = q_hist.filter(
            or_(
                HistoricoAnaliseDesfeita.centro_custo_id.in_(ccs_gestor),
                HistoricoAnaliseDesfeita.desfeito_por_id == usuario_id,
            )
        )
    else:
        q_hist = q_hist.filter(HistoricoAnaliseDesfeita.desfeito_por_id == usuario_id)

    for d in q_hist.order_by(HistoricoAnaliseDesfeita.desfeito_em.desc()).limit(200).all():
        motivo_txt = d.motivo or ''
        if motivo_txt.startswith('Transferência de Centro de Custo'):
            tipo_cod = 'TRANSFERENCIA'
            tipo_lbl = 'Transferência de Setor'
        elif motivo_txt.startswith('Devolução de Centro de Custo'):
            tipo_cod = 'DEVOLUCAO'
            tipo_lbl = 'Devolução de Setor'
        else:
            tipo_cod = 'DESFEITA'
            tipo_lbl = 'Análise Desfeita'

        outro_perfil = int(d.desfeito_por_id) != int(usuario_id)
        eventos.append({
            'ts': d.desfeito_em.isoformat() if d.desfeito_em else '',
            'data_hora': (d.desfeito_em - timedelta(hours=3)).strftime('%d/%m/%Y %H:%M') if d.desfeito_em else '--',
            'tipo': tipo_cod,
            'tipo_label': tipo_lbl,
            'colaborador': f"{d.cracha} - {d.colab_nome}",
            'data_falta': d.data_ocorrencia.strftime('%d/%m/%Y') if d.data_ocorrencia else '--',
            'setor': f"{d.codigo_cc} - {d.cc_nome}",
            'detalhe': motivo_txt or '--',
            'executado_por': f"{d.autor_nome} ({d.autor_role})",
            'outro_perfil': outro_perfil,
        })

    eventos.sort(key=lambda x: x['ts'], reverse=True)

    return jsonify({
        'sucesso': True,
        'gestor': {
            'id': user.id,
            'cracha': user.colaborador.cracha,
            'nome': user.colaborador.nome,
        },
        'movimentacoes': eventos
    }), 200


@api_bp.route('/faltas/<int:ocorrencia_id>/desfazer-analise', methods=['POST'])
def desfazer_analise_falta(ocorrencia_id):
    id_user = session.get('usuario_id')
    perfil = session.get('usuario_perfil')
    if not id_user:
        return jsonify({'sucesso': False, 'mensagem': 'Não autenticado.'}), 401

    data = request.json or {}
    motivo = str(data.get('motivo') or '').strip()
    if not motivo:
        return jsonify({'sucesso': False, 'mensagem': 'Informe o motivo para desfazer a análise.'}), 400

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
            return jsonify({'sucesso': False, 'mensagem': 'Sem permissão para este Centro de Custo.'}), 403

    if ocorrencia.status != 'ANALISADA':
        db.rollback()
        return jsonify({'sucesso': False, 'mensagem': 'Esta ocorrência não está analisada.'}), 400

    analise_atual = db.query(AnaliseFalta).filter(AnaliseFalta.ocorrencia_id == ocorrencia.id).first()
    snapshot = None
    if analise_atual:
        snapshot = json.dumps({
            'ausencia_programada': analise_atual.ausencia_programada,
            'comunicada_2h_antecedencia': analise_atual.comunicada_2h_antecedencia,
            'autorizado_hora_extra': analise_atual.autorizado_hora_extra,
            'autorizador_he_nome': analise_atual.autorizador_he_nome,
            'conseguiu_he_cobertura': analise_atual.conseguiu_he_cobertura,
            'cobridor_colaborador_id': analise_atual.cobridor_colaborador_id,
            'redividiu_equipe': analise_atual.redividiu_equipe,
            'qtd_pacientes': analise_atual.qtd_pacientes,
            'qtd_colaboradores': analise_atual.qtd_colaboradores,
            'justificativa_nao_redimensionada': analise_atual.justificativa_nao_redimensionada,
        }, default=str)

    registro_hist = HistoricoAnaliseDesfeita(
        ocorrencia_id=ocorrencia.id,
        colaborador_id=ocorrencia.colaborador_id,
        centro_custo_id=ocorrencia.centro_custo_id,
        data_ocorrencia=ocorrencia.data_ocorrencia,
        desfeito_por_id=id_user,
        motivo=motivo,
        dados_analise_anterior=snapshot,
    )
    db.add(registro_hist)

    db.query(AnaliseFalta).filter(AnaliseFalta.ocorrencia_id == ocorrencia.id).delete(synchronize_session=False)
    ocorrencia.status = 'PENDENTE'
    db.commit()

    return jsonify({'sucesso': True, 'mensagem': 'Análise desfeita e motivo salvo no histórico!'}), 200


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

        usuario_existente = (
            db.query(Usuario.id, Usuario.role, Usuario.ativo)
            .filter(Usuario.colaborador_id == colab.id)
            .first()
        )
        if usuario_existente:
            status_txt = "ATIVO" if usuario_existente.ativo else "BLOQUEADO"
            return jsonify({
                'sucesso': False,
                'mensagem': (
                    f'O crachá {cracha} ({colab.nome}) já possui acesso liberado '
                    f'(Perfil: {usuario_existente.role} • {status_txt}). Gerencie o perfil na aba Gestão de Perfis.'
                )
            }), 409

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


# ==============================================================================
# GESTÃO DE PERFIS (GESTORES E ROOT)
# ==============================================================================
@api_bp.route('/gestores', methods=['GET'])
def listar_gestores():
    if session.get('usuario_perfil') != 'ROOT':
        return jsonify({'sucesso': False, 'mensagem': 'Acesso negado.'}), 403

    db = get_db()
    usuarios = (
        db.query(Usuario)
        .options(
            joinedload(Usuario.colaborador).load_only(Colaborador.cracha, Colaborador.nome),
            selectinload(Usuario.centros_custo)
            .joinedload(UsuarioCentroCusto.centro_custo)
            .load_only(CentroCusto.id, CentroCusto.codigo_cc, CentroCusto.nome)
        )
        .order_by(Usuario.role.desc(), Usuario.id.asc())
        .all()
    )

    return jsonify({
        'sucesso': True,
        'usuario_logado_id': session.get('usuario_id'),
        'gestores': [
            {
                'id': u.id,
                'cracha': u.colaborador.cracha,
                'nome': u.colaborador.nome,
                'role': (u.role or 'GESTOR').upper(),
                'ativo': u.ativo,
                'centros_custo': [f"{uc.centro_custo.codigo_cc} - {uc.centro_custo.nome}" for uc in u.centros_custo],
                'centros_custo_ids': [uc.centro_custo_id for uc in u.centros_custo]
            } for u in usuarios
        ]
    }), 200


@api_bp.route('/gestores/<int:usuario_id>/centros-custo', methods=['PUT'])
def atualizar_ccs_gestor(usuario_id):
    if session.get('usuario_perfil') != 'ROOT':
        return jsonify({'sucesso': False, 'mensagem': 'Acesso negado.'}), 403

    data = request.json or {}
    novos_ids = {int(cc_id) for cc_id in data.get('centros_custo_ids', [])}

    db = get_db()
    user = db.query(Usuario).filter(Usuario.id == usuario_id).first()
    if not user:
        return jsonify({'sucesso': False, 'mensagem': 'Usuário não encontrado.'}), 404

    if (user.role or '').upper() == 'ROOT':
        return jsonify({'sucesso': False, 'mensagem': 'Usuários ROOT não possuem vínculo com Centros de Custo.'}), 400

    if not novos_ids:
        return jsonify({'sucesso': False, 'mensagem': 'Selecione ao menos 1 Centro de Custo para o Gestor.'}), 400

    db.query(UsuarioCentroCusto).filter(UsuarioCentroCusto.usuario_id == usuario_id).delete(synchronize_session=False)
    db.bulk_save_objects([
        UsuarioCentroCusto(usuario_id=usuario_id, centro_custo_id=cc_id)
        for cc_id in novos_ids
    ])

    db.commit()
    return jsonify({'sucesso': True, 'mensagem': 'Centros de Custo atualizados com sucesso!'}), 200


@api_bp.route('/gestores/<int:usuario_id>/privilegios', methods=['PUT'])
def atualizar_privilegios_gestor(usuario_id):
    if session.get('usuario_perfil') != 'ROOT':
        return jsonify({'sucesso': False, 'mensagem': 'Acesso negado.'}), 403

    data = request.json or {}
    novo_role = str(data.get('role', '')).strip().upper()
    if novo_role not in ('ROOT', 'GESTOR'):
        return jsonify({'sucesso': False, 'mensagem': 'Perfil inválido. Escolha GESTOR ou ROOT.'}), 400

    if usuario_id == session.get('usuario_id') and novo_role != 'ROOT':
        return jsonify({'sucesso': False, 'mensagem': 'Você não pode remover seu próprio privilégio ROOT.'}), 400

    db = get_db()
    user = db.query(Usuario).filter(Usuario.id == usuario_id).first()
    if not user:
        return jsonify({'sucesso': False, 'mensagem': 'Usuário não encontrado.'}), 404

    if user.role == 'ROOT' and novo_role == 'GESTOR':
        total_roots = (
            db.query(func.count(Usuario.id))
            .filter(Usuario.role == 'ROOT', Usuario.ativo.is_(True))
            .scalar() or 0
        )
        if total_roots <= 1:
            return jsonify({'sucesso': False, 'mensagem': 'O sistema deve manter ao menos 1 administrador ROOT ativo.'}), 400

    user.role = novo_role

    if novo_role == 'ROOT':
        db.query(UsuarioCentroCusto).filter(UsuarioCentroCusto.usuario_id == usuario_id).delete(synchronize_session=False)

    db.commit()
    return jsonify({
        'sucesso': True,
        'mensagem': f'Privilégio atualizado para {novo_role} com sucesso!'
    }), 200


@api_bp.route('/gestores/<int:usuario_id>/senha', methods=['PUT'])
def atualizar_senha_gestor(usuario_id):
    if session.get('usuario_perfil') != 'ROOT':
        return jsonify({'sucesso': False, 'mensagem': 'Acesso negado.'}), 403

    data = request.json or {}
    nova_senha = str(data.get('nova_senha', '')).strip()
    if len(nova_senha) < 6:
        return jsonify({'sucesso': False, 'mensagem': 'A nova senha deve ter no mínimo 6 caracteres.'}), 400

    db = get_db()
    user = db.query(Usuario).filter(Usuario.id == usuario_id).first()
    if not user:
        return jsonify({'sucesso': False, 'mensagem': 'Usuário não encontrado.'}), 404

    user.senha_hash = generate_password_hash(nova_senha)
    db.commit()
    return jsonify({'sucesso': True, 'mensagem': 'Senha redefinida com sucesso!'}), 200


@api_bp.route('/gestores/<int:usuario_id>/alternar-status', methods=['PUT'])
def alternar_status_gestor(usuario_id):
    if session.get('usuario_perfil') != 'ROOT':
        return jsonify({'sucesso': False, 'mensagem': 'Acesso negado.'}), 403

    if usuario_id == session.get('usuario_id'):
        return jsonify({'sucesso': False, 'mensagem': 'Você não pode bloquear sua própria conta.'}), 400

    db = get_db()
    user = db.query(Usuario).filter(Usuario.id == usuario_id).first()
    if not user:
        return jsonify({'sucesso': False, 'mensagem': 'Usuário não encontrado.'}), 404

    if user.role == 'ROOT' and user.ativo:
        total_roots = (
            db.query(func.count(Usuario.id))
            .filter(Usuario.role == 'ROOT', Usuario.ativo.is_(True))
            .scalar() or 0
        )
        if total_roots <= 1:
            return jsonify({'sucesso': False, 'mensagem': 'Não é possível bloquear o único ROOT ativo.'}), 400

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
    tipo = str(data.get('tipo', 'faltas')).strip().lower()

    if tipo == 'estrutura':
        res = executar_task_estrutura()
    elif tipo == 'censo':
        res = executar_task_censo()
    else:
        res = executar_task_faltas()

    status_code = 200 if res.get('sucesso') else 500
    return jsonify(res), status_code

@api_bp.route('/etl/agendamentos', methods=['GET'])
def listar_agendamentos_etl():
    if session.get('usuario_perfil') != 'ROOT':
        return jsonify({'sucesso': False, 'mensagem': 'Acesso negado.'}), 403

    return jsonify({
        'sucesso': True,
        'agendamentos': obter_status_agendadores()
    }), 200


@api_bp.route('/etl/agendamentos/<string:task_name>', methods=['POST', 'DELETE'])
def configurar_agendamento_etl(task_name):
    if session.get('usuario_perfil') != 'ROOT':
        return jsonify({'sucesso': False, 'mensagem': 'Acesso negado.'}), 403

    if request.method == 'DELETE':
        res = parar_agendador_tarefa(task_name)
        return jsonify(res), (200 if res['sucesso'] else 400)

    data = request.json or {}
    try:
        intervalo_horas = float(data.get('intervalo_horas', 2.0))
    except (TypeError, ValueError):
        return jsonify({'sucesso': False, 'mensagem': 'Intervalo inválido.'}), 400

    res = iniciar_agendador_tarefa(task_name=task_name, intervalo_horas=intervalo_horas)
    return jsonify(res), (200 if res['sucesso'] else 400)


@api_bp.route('/etl/terminal/logs', methods=['GET', 'DELETE'])
def terminal_logs_etl():
    if session.get('usuario_perfil') != 'ROOT':
        return jsonify({'sucesso': False, 'mensagem': 'Acesso negado.'}), 403

    if request.method == 'DELETE':
        limpar_logs_terminal()
        return jsonify({'sucesso': True}), 200

    after_id = request.args.get('after_id', 0, type=int)
    dados = obter_logs_terminal(after_id=after_id)
    return jsonify({'sucesso': True, **dados}), 200




@api_bp.route('/etl/sql/schema', methods=['GET'])
def obter_schema_sql_autocomplete():
    """Retorna tabelas e colunas do PostgreSQL (public) para o IntelliSense do Console SQL."""
    if session.get('usuario_perfil') != 'ROOT':
        return jsonify({'sucesso': False, 'mensagem': 'Acesso negado.'}), 403

    db = get_db()
    rows = db.execute(text("""
        SELECT table_name, column_name
        FROM information_schema.columns
        WHERE table_schema = 'public'
        ORDER BY table_name, ordinal_position
    """)).fetchall()

    schema_map = {}
    for table_name, column_name in rows:
        schema_map.setdefault(table_name, []).append(column_name)

    return jsonify({
        'sucesso': True,
        'tables': schema_map
    }), 200


@api_bp.route('/etl/sql/executar', methods=['POST'])
def executar_sql_console():
    """Executa exclusivamente consultas de leitura (SELECT / WITH) no PostgreSQL da aplicação."""
    if session.get('usuario_perfil') != 'ROOT':
        return jsonify({'sucesso': False, 'mensagem': 'Acesso negado.'}), 403

    data = request.json or {}
    sql_raw = str(data.get('sql') or '').strip()

    if not sql_raw:
        return jsonify({'sucesso': False, 'mensagem': 'Digite uma consulta SELECT antes de executar.'}), 400

    # Remove comentários SQL (-- e /* */) apenas para validar comandos ocultos
    sql_sem_comentarios = re.sub(r'--.*?$|/\*.*?\*/', '', sql_raw, flags=re.MULTILINE | re.DOTALL).strip()
    sql_limpo = sql_sem_comentarios.rstrip(';').strip()

    # Bloqueia múltiplas queries encadeadas com ';'
    if ';' in sql_limpo:
        return jsonify({
            'sucesso': False,
            'mensagem': 'Por segurança, execute apenas uma consulta SELECT por vez.'
        }), 400

    primeira_palavra = sql_limpo.split()[0].upper() if sql_limpo.split() else ''
    if primeira_palavra not in ('SELECT', 'WITH'):
        return jsonify({
            'sucesso': False,
            'mensagem': 'Console restrito a consultas de leitura (SELECT / WITH).'
        }), 403

    if PALAVRAS_PROIBIDAS_SQL.search(sql_limpo):
        return jsonify({
            'sucesso': False,
            'mensagem': 'Comando bloqueado: operações de escrita ou alteração de estrutura não são permitidas.'
        }), 403

    usuario_nome = session.get('usuario_nome', 'ROOT')
    registrar_log(f"🔎 [READ-ONLY] SQL executado por {usuario_nome}: {sql_limpo[:140]}", nivel="INFO", origem="SQL")

    db = get_db()
    try:
        # Garante transação estritamente somente-leitura no PostgreSQL
        db.execute(text("SET TRANSACTION READ ONLY"))
        result = db.execute(text(sql_limpo))

        colunas = list(result.keys()) if result.returns_rows else []
        rows_raw = result.fetchmany(200) if result.returns_rows else []
        db.rollback()

        linhas = [
            [val.isoformat() if hasattr(val, 'isoformat') else (str(val) if val is not None else None) for val in r]
            for r in rows_raw
        ]
        registrar_log(f"✅ [SQL] Retornadas {len(linhas)} linha(s).", nivel="SUCCESS", origem="SQL")
        return jsonify({
            'sucesso': True,
            'colunas': colunas,
            'linhas': linhas,
            'total': len(linhas),
            'mensagem': f'{len(linhas)} registro(s) retornado(s) (modo somente leitura • limite 200).'
        }), 200

    except Exception as e:
        db.rollback()
        registrar_log(f"❌ [SQL] Erro: {str(e)}", nivel="ERROR", origem="SQL")
        return jsonify({'sucesso': False, 'mensagem': f'Erro SQL: {str(e)}'}), 400


@api_bp.route('/dashboard/metricas', methods=['GET'])
def dashboard_metricas():
    if session.get('usuario_perfil') != 'ROOT':
        return jsonify({'sucesso': False, 'mensagem': 'Acesso negado.'}), 403

    db = get_db()
    stats_rows = (
        db.query(OcorrenciaFalta.status, func.count(OcorrenciaFalta.id))
        .group_by(OcorrenciaFalta.status)
        .all()
    )
    stats_map = dict(stats_rows)

    total_gestores = (
        db.query(func.count(Usuario.id))
        .filter(Usuario.role == 'GESTOR', Usuario.ativo.is_(True))
        .scalar() or 0
    )
    convites_ativos = (
        db.query(func.count(ConviteAcesso.id))
        .filter(ConviteAcesso.status == 'DISPONIVEL')
        .scalar() or 0
    )

    return jsonify({
        'sucesso': True,
        'kpis': {
            'pendentes': stats_map.get('PENDENTE', 0),
            'analisadas': stats_map.get('ANALISADA', 0),
            'gestores_ativos': total_gestores,
            'convites_disponiveis': convites_ativos
        }
    }), 200

@api_bp.route('/dashboard/powerbi-url', methods=['GET'])
def obter_url_powerbi():
    if session.get('usuario_perfil') != 'ROOT':
        return jsonify({'sucesso': False, 'mensagem': 'Acesso negado.'}), 403

    return jsonify({
        'sucesso': True,
        'url': 'https://app.powerbi.com/view?r=eyJrIjoiMjAwNDc1ZTEtYzQ3OC00MTUyLWI4NjMtOTJhZDEwNDczNDdjIiwidCI6ImNlMDNjMzhjLTgxYjYtNDdmNC1hMTZmLTk4MWZmMWQzMjU3MCJ9'
    }), 200

# ==============================================================================
# PROGRAMAÇÃO ASSISTENCIAL (GESTOR) & SINCRONIZAÇÃO CENSO
# ==============================================================================
@api_bp.route('/programacao-assistencial/contexto', methods=['GET'])
def contexto_programacao_assistencial():
    id_user = session.get('usuario_id')
    if not id_user:
        return jsonify({'sucesso': False, 'mensagem': 'Não autenticado.'}), 401

    db = get_db()
    unidades_censo = (
        db.query(CensoInternacaoUnidade)
        .order_by(CensoInternacaoUnidade.nome_unidade.asc())
        .all()
    )

    if not unidades_censo:
        return jsonify({
            'sucesso': False,
            'mensagem': 'Nenhuma unidade encontrada na tabela de censo. Execute a sincronização da planilha primeiro.'
        }), 404

    nomes_disponiveis = [u.nome_unidade for u in unidades_censo]
    unidade_sel = str(request.args.get('nome_unidade') or '').strip()
    if not unidade_sel or unidade_sel not in set(nomes_disponiveis):
        unidade_sel = nomes_disponiveis[0]

    data_str = str(request.args.get('data') or '').strip()
    turno_raw = str(request.args.get('turno') or '').strip().upper()
    turno = turno_raw if turno_raw in ('DIURNO', 'NOTURNO') else None

    hoje_br = (datetime.now(timezone.utc) - timedelta(hours=3)).date()
    try:
        data_prog = datetime.strptime(data_str, '%Y-%m-%d').date() if data_str else hoje_br
    except ValueError:
        data_prog = hoje_br

    censo_obj = next((u for u in unidades_censo if u.nome_unidade == unidade_sel), None)
    censo_payload = {
        'qtd_internacao': censo_obj.qtd_internacao if censo_obj else 0,
        'atualizado_em': (
            (censo_obj.atualizado_em - timedelta(hours=3)).strftime('%d/%m/%Y %H:%M')
            if censo_obj and censo_obj.atualizado_em else None
        ),
    }

    prog_payload = None
    if turno:
        prog_existente = (
            db.query(ProgramacaoAssistencial)
            .options(selectinload(ProgramacaoAssistencial.remanejamentos))
            .filter(
                ProgramacaoAssistencial.nome_unidade == unidade_sel,
                ProgramacaoAssistencial.data_programacao == data_prog,
                ProgramacaoAssistencial.turno == turno,
            )
            .first()
        )

        if prog_existente:
            detalhes_novos = []
            if prog_existente.detalhe_colaboradores_novos:
                try:
                    detalhes_novos = json.loads(prog_existente.detalhe_colaboradores_novos)
                except Exception:
                    detalhes_novos = []

            prog_payload = {
                'id': prog_existente.id,
                'turno': prog_existente.turno,
                'qtd_colaboradores_programados': prog_existente.qtd_colaboradores_programados,
                'qtd_aux_12h': prog_existente.qtd_aux_12h or prog_existente.qtd_colaboradores_programados,
                'qtd_aux_6h_manha': prog_existente.qtd_aux_6h_manha or 0,
                'qtd_aux_6h_tarde': prog_existente.qtd_aux_6h_tarde or 0,
                'tem_colaboradores_novos': bool(prog_existente.tem_colaboradores_novos),
                'qtd_colaboradores_novos': prog_existente.qtd_colaboradores_novos or 0,
                'pacientes_colaboradores_novos': prog_existente.pacientes_colaboradores_novos or 0,
                'detalhe_colaboradores_novos': detalhes_novos,
                'leitos_fisicos': prog_existente.leitos_fisicos,
                'leitos_bloqueados': prog_existente.leitos_bloqueados,
                'observacao': prog_existente.observacao or '',
                'atualizado_em': (
                    (prog_existente.atualizado_em - timedelta(hours=3)).strftime('%d/%m/%Y %H:%M')
                    if prog_existente.atualizado_em else ''
                ),
                'remanejamentos': [
                    {
                        'tipo': r.tipo,
                        'quantidade': r.quantidade,
                        'unidade_contraparte': r.unidade_contraparte,
                    }
                    for r in prog_existente.remanejamentos
                ],
            }

    return jsonify({
        'sucesso': True,
        'data_padrao': data_prog.isoformat(),
        'unidade_selecionada': unidade_sel,
        'unidades': [
            {'nome_unidade': u.nome_unidade, 'qtd_internacao': u.qtd_internacao}
            for u in unidades_censo
        ],
        'listas_autorizacao': {
            'PLANTAO_ADM': list(LISTA_PLANTAO_ADM),
            'COORDENACAO': list(LISTA_COORDENACAO),
        },
        'censo': censo_payload,
        'programacao_existente': prog_payload,
    }), 200


@api_bp.route('/programacao-assistencial', methods=['POST'])
def salvar_programacao_assistencial():
    id_user = session.get('usuario_id')
    if not id_user:
        return jsonify({'sucesso': False, 'mensagem': 'Não autenticado.'}), 401

    data = request.json or {}
    nome_unidade = str(data.get('nome_unidade') or '').strip()
    turno = str(data.get('turno') or '').strip().upper()
    data_str = str(data.get('data_programacao') or '').strip()

    if not nome_unidade or turno not in ('DIURNO', 'NOTURNO') or not data_str:
        return jsonify({'sucesso': False, 'mensagem': 'Informe unidade, data e turno (Diurno ou Noturno).'}), 400

    try:
        data_prog = datetime.strptime(data_str, '%Y-%m-%d').date()
        qtd_aux_12h = max(0, int(data.get('qtd_aux_12h') or 0))
        qtd_aux_6h_manha = max(0, int(data.get('qtd_aux_6h_manha') or 0))
        qtd_aux_6h_tarde = max(0, int(data.get('qtd_aux_6h_tarde') or 0))
        qtd_prog = int(data.get('qtd_colaboradores_programados') or (qtd_aux_12h + qtd_aux_6h_manha + qtd_aux_6h_tarde))
        leitos_fisicos = int(data.get('leitos_fisicos') or 0)
        leitos_bloqueados = int(data.get('leitos_bloqueados') or 0)
    except (TypeError, ValueError):
        return jsonify({'sucesso': False, 'mensagem': 'Valores numéricos inválidos.'}), 400

    if qtd_prog < 1 or leitos_fisicos < 1:
        return jsonify({'sucesso': False, 'mensagem': 'Informe a equipe de Aux/Tec Enfermagem e os leitos disponíveis.'}), 400

    if leitos_bloqueados < 0 or leitos_bloqueados > leitos_fisicos:
        return jsonify({'sucesso': False, 'mensagem': 'Leitos bloqueados não pode exceder os leitos disponíveis.'}), 400

    tem_colab_novos = bool(data.get('tem_colaboradores_novos'))
    detalhes_novos_raw = data.get('detalhe_colaboradores_novos') or []
    qtd_colab_novos = 0
    pac_colab_novos = 0
    detalhes_novos_limpos = []

    if tem_colab_novos:
        for idx, item in enumerate(detalhes_novos_raw, start=1):
            try:
                qtd_pac_item = int(item.get('pacientes') or 0)
            except (TypeError, ValueError):
                qtd_pac_item = 0
            if qtd_pac_item < 1:
                return jsonify({
                    'sucesso': False,
                    'mensagem': f'Informe a quantidade de pacientes do Colaborador {idx:02d}.'
                }), 400
            detalhes_novos_limpos.append({'colaborador': idx, 'pacientes': qtd_pac_item})
            pac_colab_novos += qtd_pac_item
        qtd_colab_novos = len(detalhes_novos_limpos)
        if qtd_colab_novos < 1:
            return jsonify({'sucesso': False, 'mensagem': 'Informe a quantidade de colaboradores novos.'}), 400

    remanejamentos_raw = data.get('remanejamentos') or []
    qtd_emprestados = 0
    qtd_recebidos = 0
    itens_remanejamento = []

    for item in remanejamentos_raw:
        tipo_rem = str(item.get('tipo') or '').strip().upper()
        qtd_rem = int(item.get('quantidade') or 0)
        contra_nome = str(item.get('unidade_contraparte') or '').strip()
        if tipo_rem not in ('EMPRESTIMO', 'RECEBIMENTO') or qtd_rem < 1 or not contra_nome or contra_nome == nome_unidade:
            continue
        if tipo_rem == 'EMPRESTIMO':
            qtd_emprestados += qtd_rem
        else:
            qtd_recebidos += qtd_rem
        itens_remanejamento.append(
            RemanejamentoAssistencial(
                tipo=tipo_rem,
                quantidade=qtd_rem,
                unidade_contraparte=contra_nome,
            )
        )

    hora_extra_info = data.get('hora_extra') or {}
    if hora_extra_info.get('ativo'):
        aut_he = str(hora_extra_info.get('autorizador') or '').strip()
        just_he = str(hora_extra_info.get('justificativa') or '').strip()
        permitidos = set(LISTA_PLANTAO_ADM) | set(LISTA_COORDENACAO)
        if not aut_he or aut_he not in permitidos:
            return jsonify({'sucesso': False, 'mensagem': 'Selecione o responsável que autorizou a Hora Extra.'}), 400
        if not just_he:
            return jsonify({'sucesso': False, 'mensagem': 'Informe a justificativa da Hora Extra.'}), 400

    qtd_efetivos = qtd_prog - qtd_emprestados + qtd_recebidos
    if qtd_efetivos < 1:
        return jsonify({'sucesso': False, 'mensagem': 'O total de colaboradores efetivos no turno não pode ser menor que 1.'}), 400

    db = get_db()
    censo = db.query(CensoInternacaoUnidade).filter(CensoInternacaoUnidade.nome_unidade == nome_unidade).first()
    pacientes_internados = censo.qtd_internacao if censo else 0

    leitos_operacionais = max(0, leitos_fisicos - leitos_bloqueados)
    leitos_vagos = max(0, leitos_operacionais - pacientes_internados)
    taxa_ocupacao = round((pacientes_internados / leitos_operacionais) * 100, 2) if leitos_operacionais > 0 else 0
    pacientes_por_colab = round(pacientes_internados / qtd_efetivos, 2)
    leitos_por_colab = round(leitos_operacionais / qtd_efetivos, 2)
    observacao_txt = str(data.get('observacao') or '').strip() or None
    detalhe_novos_json = json.dumps(detalhes_novos_limpos) if tem_colab_novos else None

    try:
        prog = (
            db.query(ProgramacaoAssistencial)
            .filter(
                ProgramacaoAssistencial.nome_unidade == nome_unidade,
                ProgramacaoAssistencial.data_programacao == data_prog,
                ProgramacaoAssistencial.turno == turno,
            )
            .with_for_update()
            .first()
        )

        agora_utc = datetime.now(timezone.utc)
        if not prog:
            prog = ProgramacaoAssistencial(
                nome_unidade=nome_unidade,
                gestor_id=id_user,
                data_programacao=data_prog,
                turno=turno,
                qtd_colaboradores_programados=qtd_prog,
                qtd_aux_12h=qtd_aux_12h,
                qtd_aux_6h_manha=qtd_aux_6h_manha,
                qtd_aux_6h_tarde=qtd_aux_6h_tarde,
                tem_colaboradores_novos=tem_colab_novos,
                qtd_colaboradores_novos=qtd_colab_novos,
                pacientes_colaboradores_novos=pac_colab_novos,
                detalhe_colaboradores_novos=detalhe_novos_json,
                leitos_fisicos=leitos_fisicos,
                leitos_bloqueados=leitos_bloqueados,
                qtd_emprestados=qtd_emprestados,
                qtd_recebidos=qtd_recebidos,
                qtd_colaboradores_efetivos=qtd_efetivos,
                pacientes_internados=pacientes_internados,
                leitos_operacionais=leitos_operacionais,
                leitos_vagos=leitos_vagos,
                taxa_ocupacao=taxa_ocupacao,
                pacientes_por_colaborador=pacientes_por_colab,
                leitos_por_colaborador=leitos_por_colab,
                observacao=observacao_txt,
                criado_em=agora_utc,
                atualizado_em=agora_utc,
            )
            db.add(prog)
            db.flush()
        else:
            db.query(RemanejamentoAssistencial).filter(
                RemanejamentoAssistencial.programacao_id == prog.id
            ).delete(synchronize_session=False)

            prog.gestor_id = id_user
            prog.qtd_colaboradores_programados = qtd_prog
            prog.qtd_aux_12h = qtd_aux_12h
            prog.qtd_aux_6h_manha = qtd_aux_6h_manha
            prog.qtd_aux_6h_tarde = qtd_aux_6h_tarde
            prog.tem_colaboradores_novos = tem_colab_novos
            prog.qtd_colaboradores_novos = qtd_colab_novos
            prog.pacientes_colaboradores_novos = pac_colab_novos
            prog.detalhe_colaboradores_novos = detalhe_novos_json
            prog.leitos_fisicos = leitos_fisicos
            prog.leitos_bloqueados = leitos_bloqueados
            prog.qtd_emprestados = qtd_emprestados
            prog.qtd_recebidos = qtd_recebidos
            prog.qtd_colaboradores_efetivos = qtd_efetivos
            prog.pacientes_internados = pacientes_internados
            prog.leitos_operacionais = leitos_operacionais
            prog.leitos_vagos = leitos_vagos
            prog.taxa_ocupacao = taxa_ocupacao
            prog.pacientes_por_colaborador = pacientes_por_colab
            prog.leitos_por_colaborador = leitos_por_colab
            prog.observacao = observacao_txt
            prog.atualizado_em = agora_utc

        for rem in itens_remanejamento:
            rem.programacao_id = prog.id
            db.add(rem)

        db.commit()
        return jsonify({
            'sucesso': True,
            'mensagem': f'Programação Assistencial ({turno}) registrada com sucesso!',
        }), 200
    except Exception as e:
        db.rollback()
        print(f"❌ [ERRO SALVAR PROGRAMACAO] {e}")
        return jsonify({'sucesso': False, 'mensagem': f'Erro ao salvar programação: {str(e)}'}), 500


@api_bp.route('/programacao-assistencial/historico', methods=['GET'])
def historico_programacao_assistencial():
    """Retorna os relatórios anteriores lançados pelo gestor ordenados do mais recente para o mais antigo."""
    id_user = session.get('usuario_id')
    perfil = session.get('usuario_perfil')
    if not id_user:
        return jsonify({'sucesso': False, 'mensagem': 'Não autenticado.'}), 401

    db = get_db()
    q = (
        db.query(ProgramacaoAssistencial)
        .options(
            joinedload(ProgramacaoAssistencial.gestor).joinedload(Usuario.colaborador),
            selectinload(ProgramacaoAssistencial.remanejamentos),
        )
    )

    if perfil != 'ROOT':
        q = q.filter(ProgramacaoAssistencial.gestor_id == id_user)

    rows = (
        q.order_by(
            ProgramacaoAssistencial.atualizado_em.desc(),
            ProgramacaoAssistencial.data_programacao.desc(),
            ProgramacaoAssistencial.id.desc(),
        )
        .limit(80)
        .all()
    )

    relatorios = []
    for p in rows:
        detalhes_novos = []
        if p.detalhe_colaboradores_novos:
            try:
                detalhes_novos = json.loads(p.detalhe_colaboradores_novos)
            except Exception:
                detalhes_novos = []

        relatorios.append({
            'id': p.id,
            'nome_unidade': p.nome_unidade,
            'data_iso': p.data_programacao.isoformat(),
            'data_br': p.data_programacao.strftime('%d/%m/%Y'),
            'turno': (p.turno or 'DIURNO').strip().upper(),
            'qtd_programados': p.qtd_colaboradores_programados,
            'qtd_aux_12h': p.qtd_aux_12h or p.qtd_colaboradores_programados,
            'qtd_aux_6h_manha': p.qtd_aux_6h_manha or 0,
            'qtd_aux_6h_tarde': p.qtd_aux_6h_tarde or 0,
            'tem_colaboradores_novos': bool(p.tem_colaboradores_novos),
            'qtd_colaboradores_novos': p.qtd_colaboradores_novos or 0,
            'pacientes_colaboradores_novos': p.pacientes_colaboradores_novos or 0,
            'detalhe_colaboradores_novos': detalhes_novos,
            'qtd_emprestados': p.qtd_emprestados,
            'qtd_recebidos': p.qtd_recebidos,
            'qtd_efetivos': p.qtd_colaboradores_efetivos,
            'leitos_fisicos': p.leitos_fisicos,
            'leitos_bloqueados': p.leitos_bloqueados,
            'leitos_operacionais': p.leitos_operacionais,
            'pacientes_internados': p.pacientes_internados,
            'leitos_vagos': p.leitos_vagos,
            'taxa_ocupacao': float(p.taxa_ocupacao or 0),
            'pacientes_por_colaborador': float(p.pacientes_por_colaborador or 0),
            'leitos_por_colaborador': float(p.leitos_por_colaborador or 0),
            'observacao': p.observacao or '',
            'gestor_nome': p.gestor.colaborador.nome if p.gestor and p.gestor.colaborador else '--',
            'atualizado_em': (p.atualizado_em - timedelta(hours=3)).strftime('%d/%m/%Y %H:%M') if p.atualizado_em else '--',
            'remanejamentos': [
                {
                    'tipo': r.tipo,
                    'quantidade': r.quantidade,
                    'unidade_contraparte': r.unidade_contraparte,
                }
                for r in p.remanejamentos
            ],
        })

    return jsonify({'sucesso': True, 'relatorios': relatorios}), 200

@api_bp.route('/censo/sincronizar', methods=['POST'])
def sincronizar_censo_unidades():
    """Recebe o resumo agrupado da planilha CENSO_FUNFARME.XLSX enviado pela VM da TI."""
    api_key_env = os.getenv('CENSO_SYNC_KEY', '').strip().strip("'\"")
    api_key_req = str(request.headers.get('X-API-KEY') or '').strip()

    autorizado_chave = bool(api_key_env and api_key_req and api_key_req == api_key_env)
    autorizado_root = session.get('usuario_perfil') == 'ROOT'

    if not autorizado_chave and not autorizado_root:
        return jsonify({'sucesso': False, 'mensagem': 'Não autorizado para sincronizar censo.'}), 401

    data = request.json or {}
    itens = data.get('unidades') or []
    arquivo_nome = str(data.get('arquivo') or 'CENSO_FUNFARME.XLSX').strip()[:255]

    if not isinstance(itens, list) or not itens:
        return jsonify({'sucesso': False, 'mensagem': 'Payload de unidades vazio.'}), 400

    db = get_db()
    try:
        res = persistir_censo_no_banco(db, itens)
        registrar_log(
            f"🏥 [CENSO] Sincronizado ({arquivo_nome}): {res['unidades_atualizadas']} unidades | "
            f"{res['total_internados']} internados.",
            nivel="SUCCESS",
            origem="CENSO",
        )
        return jsonify({'sucesso': True, 'mensagem': 'Censo sincronizado com sucesso!', **res}), 200
    except Exception as e:
        db.rollback()
        registrar_log(f"❌ [CENSO] Erro na sincronização: {str(e)}", nivel="ERROR", origem="CENSO")
        return jsonify({'sucesso': False, 'mensagem': f'Erro ao sincronizar censo: {str(e)}'}), 500

def _remover_acentos_upper(texto: str) -> str:
    nfd = unicodedata.normalize('NFD', str(texto or '').upper().strip())
    return ''.join(c for c in nfd if unicodedata.category(c) != 'Mn')


def _classificar_unidade_predio(nome_unidade: str) -> dict:
    """
    Extrai Complexo (HB, HCM, OUTROS), Andar (8º ANDAR .. SUBSOLO) e Bloco/Ala
    diretamente do nome da unidade da planilha CENSO_FUNFARME.XLSX.
    """
    un = _remover_acentos_upper(nome_unidade)

    # 1. Complexo Hospitalar
    if un.startswith('HCM'):
        complexo = 'HCM'
        complexo_label = 'HCM • Hospital da Criança e Maternidade'
    elif un.startswith('HB'):
        complexo = 'HB'
        complexo_label = 'FUNFARME • Hospital de Base'
    else:
        complexo = 'OUTROS'
        complexo_label = 'Unidades Externas / Ambulatórios / ICA'

    # 2. Andar
    if re.search(r'\b(SS|SSOLO|SUBSOLO)\b', un) or '-SS-' in un:
        andar_cod = 'SUBSOLO'
        andar_label = 'SUBSOLO'
        andar_ordem = 0
    elif 'TERREO' in un:
        andar_cod = 'TERREO'
        andar_label = 'TÉRREO'
        andar_ordem = 1
    else:
        m_andar = re.search(r'\b([1-8])\s*[º°O]?\b', un)
        if m_andar:
            num = int(m_andar.group(1))
            andar_cod = f'{num}_ANDAR'
            andar_label = f'{num}º ANDAR'
            andar_ordem = num + 1  # 2 a 9
        else:
            andar_cod = 'SEM_ANDAR'
            andar_label = 'ALAS ESPECIAIS'
            andar_ordem = -1

    # 3. Bloco / Ala
    m_bloco = re.search(r'\bBL(?:OCO)?\.?\s*([A-E])\b', un)
    if m_bloco:
        letra = m_bloco.group(1)
        bloco_cod = f'BLOCO_{letra}'
        bloco_label = f'BLOCO {letra}'
        bloco_ordem = {'A': 1, 'B': 2, 'C': 3, 'D': 4, 'E': 5}.get(letra, 9)
    elif 'BLA' in un:
        bloco_cod = 'BLOCO_A'
        bloco_label = 'BLOCO A'
        bloco_ordem = 1
    elif any(k in un for k in ('EMERG', 'TRIAGEM', 'PA SUS', 'URG/EMERG')):
        bloco_cod = 'EMERGENCIA'
        bloco_label = 'EMERGÊNCIA / PA'
        bloco_ordem = 6
    elif any(k in un for k in ('CC-', 'CC ', 'CENTRO CIRURGICO', 'CENTRO OBSTETRICO')):
        bloco_cod = 'CENTRO_CIRURGICO'
        bloco_label = 'CENTRO CIRÚRGICO'
        bloco_ordem = 7
    elif any(k in un for k in ('UTI', 'CARDIOINTENSIVISMO', 'INTENSIVA', 'UCIN')):
        bloco_cod = 'UTI'
        bloco_label = 'TERAPIA INTENSIVA'
        bloco_ordem = 8
    else:
        bloco_cod = 'GERAL'
        bloco_label = 'ENFERMARIA / GERAL'
        bloco_ordem = 9

    return {
        'complexo': complexo,
        'complexo_label': complexo_label,
        'andar_cod': andar_cod,
        'andar_label': andar_label,
        'andar_ordem': andar_ordem,
        'bloco_cod': bloco_cod,
        'bloco_label': bloco_label,
        'bloco_ordem': bloco_ordem,
    }


@api_bp.route('/root/mapa-assistencial', methods=['GET'])
def root_mapa_assistencial():
    """
    Consolida o Censo em tempo real (CENSO_FUNFARME.XLSX) com os resumos enviados
    na Programação Assistencial por Data e Turno para a visão arquitetônica do ROOT.
    """
    if session.get('usuario_perfil') != 'ROOT':
        return jsonify({'sucesso': False, 'mensagem': 'Acesso negado.'}), 403

    data_str = str(request.args.get('data') or '').strip()
    turno = str(request.args.get('turno') or 'DIURNO').strip().upper()
    if turno not in ('DIURNO', 'NOTURNO'):
        turno = 'DIURNO'

    hoje_br = (datetime.now(timezone.utc) - timedelta(hours=3)).date()
    try:
        data_ref = datetime.strptime(data_str, '%Y-%m-%d').date() if data_str else hoje_br
    except ValueError:
        data_ref = hoje_br

    db = get_db()

    unidades_censo = (
        db.query(CensoInternacaoUnidade)
        .order_by(CensoInternacaoUnidade.nome_unidade.asc())
        .all()
    )

    programacoes = (
        db.query(ProgramacaoAssistencial)
        .options(
            joinedload(ProgramacaoAssistencial.gestor).joinedload(Usuario.colaborador),
            selectinload(ProgramacaoAssistencial.remanejamentos),
        )
        .filter(
            ProgramacaoAssistencial.data_programacao == data_ref,
            ProgramacaoAssistencial.turno == turno,
        )
        .all()
    )
    prog_por_unidade = {p.nome_unidade: p for p in programacoes}

    # Garante inclusão mesmo se alguma programação existir para unidade ausente no censo atual
    todos_nomes = sorted(
        {u.nome_unidade for u in unidades_censo} | set(prog_por_unidade.keys())
    )
    censo_map = {u.nome_unidade: u for u in unidades_censo}

    complexos_dict = {}
    resumo_geral = {
        'total_unidades': len(todos_nomes),
        'unidades_programadas': 0,
        'unidades_pendentes': 0,
        'total_internados': 0,
        'total_leitos_fisicos': 0,
        'total_leitos_bloqueados': 0,
        'total_leitos_operacionais': 0,
        'total_leitos_vagos': 0,
        'total_colab_programados': 0,
        'total_colab_efetivos': 0,
        'censo_atualizado_em': None,
    }

    ultima_sync = max((u.atualizado_em for u in unidades_censo if u.atualizado_em), default=None)
    if ultima_sync:
        resumo_geral['censo_atualizado_em'] = (ultima_sync - timedelta(hours=3)).strftime('%d/%m/%Y %H:%M')

    for nome_un in todos_nomes:
        meta = _classificar_unidade_predio(nome_un)
        censo_obj = censo_map.get(nome_un)
        prog_obj = prog_por_unidade.get(nome_un)

        internados_censo = censo_obj.qtd_internacao if censo_obj else 0

        if prog_obj:
            resumo_geral['unidades_programadas'] += 1
            internados = prog_obj.pacientes_internados
            leitos_fisicos = prog_obj.leitos_fisicos
            leitos_bloq = prog_obj.leitos_bloqueados
            leitos_op = prog_obj.leitos_operacionais
            leitos_vagos = prog_obj.leitos_vagos
            taxa_ocup = float(prog_obj.taxa_ocupacao or 0)
            qtd_prog = prog_obj.qtd_colaboradores_programados
            qtd_emp = prog_obj.qtd_emprestados
            qtd_rec = prog_obj.qtd_recebidos
            qtd_efet = prog_obj.qtd_colaboradores_efetivos
            pac_colab = float(prog_obj.pacientes_por_colaborador or 0)
            leitos_colab = float(prog_obj.leitos_por_colaborador or 0)

            resumo_geral['total_leitos_fisicos'] += leitos_fisicos
            resumo_geral['total_leitos_bloqueados'] += leitos_bloq
            resumo_geral['total_leitos_operacionais'] += leitos_op
            resumo_geral['total_leitos_vagos'] += leitos_vagos
            resumo_geral['total_colab_programados'] += qtd_prog
            resumo_geral['total_colab_efetivos'] += qtd_efet

            if taxa_ocup >= 95 or pac_colab >= 6.0:
                status_criticidade = 'CRITICO'
            elif taxa_ocup >= 85 or pac_colab >= 4.5:
                status_criticidade = 'ATENCAO'
            else:
                status_criticidade = 'NORMAL'

            detalhe_prog = {
                'programado': True,
                'gestor_nome': (
                    prog_obj.gestor.colaborador.nome
                    if prog_obj.gestor and prog_obj.gestor.colaborador else '--'
                ),
                'atualizado_em': (
                    (prog_obj.atualizado_em - timedelta(hours=3)).strftime('%d/%m/%Y %H:%M')
                    if prog_obj.atualizado_em else '--'
                ),
                'qtd_programados': qtd_prog,
                'qtd_emprestados': qtd_emp,
                'qtd_recebidos': qtd_rec,
                'qtd_efetivos': qtd_efet,
                'leitos_fisicos': leitos_fisicos,
                'leitos_bloqueados': leitos_bloq,
                'leitos_operacionais': leitos_op,
                'leitos_vagos': leitos_vagos,
                'taxa_ocupacao': taxa_ocup,
                'pacientes_por_colaborador': pac_colab,
                'leitos_por_colaborador': leitos_colab,
                'observacao': prog_obj.observacao or '',
                'remanejamentos': [
                    {
                        'tipo': r.tipo,
                        'quantidade': r.quantidade,
                        'unidade_contraparte': r.unidade_contraparte,
                    }
                    for r in prog_obj.remanejamentos
                ],
            }
        else:
            resumo_geral['unidades_pendentes'] += 1
            internados = internados_censo
            status_criticidade = 'PENDENTE'
            detalhe_prog = {
                'programado': False,
                'gestor_nome': None,
                'atualizado_em': None,
                'qtd_programados': 0,
                'qtd_emprestados': 0,
                'qtd_recebidos': 0,
                'qtd_efetivos': 0,
                'leitos_fisicos': 0,
                'leitos_bloqueados': 0,
                'leitos_operacionais': 0,
                'leitos_vagos': 0,
                'taxa_ocupacao': 0,
                'pacientes_por_colaborador': 0,
                'leitos_por_colaborador': 0,
                'observacao': '',
                'remanejamentos': [],
            }

        resumo_geral['total_internados'] += internados

        unidade_item = {
            'nome_unidade': nome_un,
            'pacientes_internados': internados,
            'internados_censo_atual': internados_censo,
            'status_criticidade': status_criticidade,
            'bloco_cod': meta['bloco_cod'],
            'bloco_label': meta['bloco_label'],
            **detalhe_prog,
        }

        comp_entry = complexos_dict.setdefault(meta['complexo'], {
            'complexo': meta['complexo'],
            'complexo_label': meta['complexo_label'],
            'andares_map': {},
        })
        andar_entry = comp_entry['andares_map'].setdefault(meta['andar_cod'], {
            'andar_cod': meta['andar_cod'],
            'andar_label': meta['andar_label'],
            'andar_ordem': meta['andar_ordem'],
            'blocos_map': {},
        })
        bloco_entry = andar_entry['blocos_map'].setdefault(meta['bloco_cod'], {
            'bloco_cod': meta['bloco_cod'],
            'bloco_label': meta['bloco_label'],
            'bloco_ordem': meta['bloco_ordem'],
            'unidades': [],
        })
        bloco_entry['unidades'].append(unidade_item)

    complexos_ordenados = []
    for comp_key in ('HB', 'HCM', 'OUTROS'):
        comp = complexos_dict.get(comp_key)
        if not comp:
            continue
        andares_list = sorted(
            comp['andares_map'].values(),
            key=lambda a: a['andar_ordem'],
            reverse=True,
        )
        for a in andares_list:
            blocos_list = sorted(a['blocos_map'].values(), key=lambda b: b['bloco_ordem'])
            a['blocos'] = blocos_list
            del a['blocos_map']
        complexos_ordenados.append({
            'complexo': comp['complexo'],
            'complexo_label': comp['complexo_label'],
            'andares': andares_list,
        })

    return jsonify({
        'sucesso': True,
        'data_iso': data_ref.isoformat(),
        'data_br': data_ref.strftime('%d/%m/%Y'),
        'turno': turno,
        'resumo': resumo_geral,
        'complexos': complexos_ordenados,
    }), 200    