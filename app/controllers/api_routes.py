import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from flask import Blueprint, jsonify, request, session
from sqlalchemy import func, or_
from sqlalchemy.orm import joinedload, selectinload, aliased
from werkzeug.security import check_password_hash, generate_password_hash
import json
from app import get_db
from app.models.models import (
    Colaborador, CentroCusto, Cargo, Usuario, UsuarioCentroCusto,
    ConviteAcesso, ConviteCentroCusto, OcorrenciaFalta, AnaliseFalta,
    LogEnvioEmail,HistoricoAnaliseDesfeita
)
from app.services.etl_estrutura import ETLEstruturaSenior
from app.services.etl_faltas import ETLFaltasDiario
from app.services.notificador_email import NotificadorEmail

COORDENADORES_AUTORIZADORES = {
    "Ana Paula Augusto Valverde",
    "Débora Augusto Valverde",
    "Janaina Souza de Lima",
    "Kátia Luciana Franca Pereira",
    "Rafaela Marqui",
    "Suzilene Ribeiro",
    "Juliane Cristina Souza Ferraroni",
}

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


@api_bp.route('/faltas/<int:ocorrencia_id>/mover-cc', methods=['PUT'])
def mover_centro_custo_ocorrencia(ocorrencia_id):
    """Move o colaborador e todas as faltas dele para o novo Centro de Custo; se houver falta ANALISADA, desfaz a análise para o novo setor."""
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

        # Busca todas as faltas vinculadas ao colaborador para mover todas juntas
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

    cc_ids = None
    if perfil != 'ROOT':
        cc_ids = _obter_ccs_usuario(db, id_user)
        if not cc_ids:
            return jsonify({
                'sucesso': True,
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
            dt_resp = (a.respondido_em - timedelta(hours=3)).strftime('%d/%m/%Y %H:%M')
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

    lista = [
        {
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
            'analise': analises_map.get(r.id)
        }
        for r in rows
    ]

    return jsonify({
        'sucesso': True,
        'faltas': lista,
        'kpis_gestor': {
            'pendentes': kpi_map.get('PENDENTE', 0),
            'analisadas': kpi_map.get('ANALISADA', 0)
        }
    }), 200


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
    autorizador_he_nome = str(data.get('autorizador_he_nome') or '').strip() or None
    conseguiu_he = bool(data.get('conseguiu_he_cobertura')) if autorizado_he else False
    cobridor_id_raw = data.get('cobridor_colaborador_id')

    if autorizado_he:
        if not autorizador_he_nome or autorizador_he_nome not in COORDENADORES_AUTORIZADORES:
            db.rollback()
            return jsonify({'sucesso': False, 'mensagem': 'Selecione o coordenador que autorizou as horas extras.'}), 400
    else:
        autorizador_he_nome = None

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
            return jsonify({'sucesso': False, 'mensagem': 'Informe se a equipe foi redimensionada.'}), 400

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
            justificativa_texto = str(data.get('justificativa_nao_redimensionada') or '').strip()
            if not justificativa_texto:
                db.rollback()
                return jsonify({
                    'sucesso': False,
                    'mensagem': 'Descreva o que foi feito na ausência do colaborador.'
                }), 400

    nova_analise = AnaliseFalta(
        ocorrencia_id=ocorrencia.id,
        avaliador_id=id_user,
        ausencia_programada=False,
        comunicada_2h_antecedencia=comunicada_2h,
        foi_troca_folga=False,
        autorizado_hora_extra=autorizado_he,
        autorizador_he_nome=autorizador_he_nome,
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


# ==============================================================================
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