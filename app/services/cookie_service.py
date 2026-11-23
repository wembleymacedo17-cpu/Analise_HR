import os
import secrets
from datetime import datetime, timedelta, timezone
from flask import session

INATIVIDADE_MAXIMA_MINUTOS = 30


class CookieService:
    @staticmethod
    def configurar_seguranca_sessao(app):
        """Configura cookies de sessão seguros (HTTPS automático no Render)."""
        app.secret_key = os.getenv('SECRET_KEY', 'chave_secreta_analise_hr_2026')
        eh_producao = os.getenv('FLASK_ENV') == 'production' or os.getenv('RENDER') is not None

        app.config['SESSION_COOKIE_HTTPONLY'] = True
        app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
        app.config['SESSION_COOKIE_SECURE'] = eh_producao
        app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

    @staticmethod
    def iniciar_sessao_usuario(db, usuario_row) -> str:
        """
        Gera um novo session_token exclusivo no banco (derrubando sessões de outras máquinas)
        e inicializa a sessão do Flask.
        """
        from app.models.models import Usuario

        novo_token = secrets.token_hex(32)
        agora = datetime.now(timezone.utc)

        db.query(Usuario).filter(Usuario.id == usuario_row.id).update(
            {
                'session_token': novo_token,
                'ultimo_acesso_em': agora,
            },
            synchronize_session=False,
        )
        db.commit()

        session.clear()
        session.permanent = True
        session['usuario_id'] = usuario_row.id
        session['usuario_nome'] = usuario_row.nome
        session['cracha'] = usuario_row.cracha
        session['usuario_perfil'] = (usuario_row.role or 'GESTOR').strip().upper()
        session['session_token'] = novo_token

        return novo_token

    @staticmethod
    def validar_sessao_unica_e_atividade(db) -> tuple[bool, str | None, str | None]:
        """
        Valida se o usuário logado continua ativo, se não logou em outro dispositivo
        e se não ultrapassou 30 minutos de inatividade.
        Retorna: (valida, codigo_motivo, mensagem_amigavel)
        """
        from app.models.models import Usuario

        usuario_id = session.get('usuario_id')
        token_sessao = session.get('session_token')

        if not usuario_id or not token_sessao:
            session.clear()
            return False, 'nao_autenticado', 'Sessão inválida. Faça login novamente.'

        row = (
            db.query(
                Usuario.ativo,
                Usuario.role,
                Usuario.session_token,
                Usuario.ultimo_acesso_em,
            )
            .filter(Usuario.id == usuario_id)
            .first()
        )

        if not row or not row.ativo:
            session.clear()
            return False, 'bloqueado', 'Seu acesso foi desativado. Contate o RH.'

        # 1. Verifica login simultâneo em outro dispositivo
        if not row.session_token or row.session_token != token_sessao:
            session.clear()
            return (
                False,
                'outro_dispositivo',
                'Sua conta foi acessada em outro dispositivo. Esta sessão foi desconectada.',
            )

        # 2. Verifica inatividade > 30 minutos
        agora = datetime.now(timezone.utc)
        if row.ultimo_acesso_em:
            ultimo = (
                row.ultimo_acesso_em.replace(tzinfo=timezone.utc)
                if row.ultimo_acesso_em.tzinfo is None
                else row.ultimo_acesso_em
            )
            if agora - ultimo > timedelta(minutes=INATIVIDADE_MAXIMA_MINUTOS):
                db.query(Usuario).filter(Usuario.id == usuario_id).update(
                    {'session_token': None}, synchronize_session=False
                )
                db.commit()
                session.clear()
                return (
                    False,
                    'inatividade',
                    'Sua sessão expirou após 30 minutos de inatividade. Faça login novamente.',
                )

        # Atualiza timestamp de atividade e sincroniza perfil caso tenha sido alterado pelo ROOT
        session['usuario_perfil'] = (row.role or 'GESTOR').strip().upper()
        db.query(Usuario).filter(Usuario.id == usuario_id).update(
            {'ultimo_acesso_em': agora}, synchronize_session=False
        )
        db.commit()

        return True, None, None

    @staticmethod
    def encerrar_sessao(db=None, response=None):
        """Invalida o token no banco e limpa os cookies do navegador."""
        from app.models.models import Usuario

        usuario_id = session.get('usuario_id')
        if db is not None and usuario_id:
            db.query(Usuario).filter(Usuario.id == usuario_id).update(
                {'session_token': None}, synchronize_session=False
            )
            db.commit()

        session.clear()
        session.modified = True
        if response:
            response.delete_cookie('session', path='/')
        return response
    @staticmethod
    def verificar_apenas_status(db) -> tuple[bool, str | None, str | None]:
        """
        Checa se a sessão continua válida (usado pelo heartbeat de 7s)
        SEM renovar o timestamp de atividade do usuário.
        """
        from app.models.models import Usuario

        usuario_id = session.get('usuario_id')
        token_sessao = session.get('session_token')

        if not usuario_id or not token_sessao:
            session.clear()
            return False, 'nao_autenticado', 'Sessão encerrada.'

        row = (
            db.query(Usuario.ativo, Usuario.session_token, Usuario.ultimo_acesso_em)
            .filter(Usuario.id == usuario_id)
            .first()
        )

        if not row or not row.ativo:
            session.clear()
            return False, 'bloqueado', 'Seu acesso foi desativado. Contate o RH.'

        if not row.session_token or row.session_token != token_sessao:
            session.clear()
            return (
                False,
                'outro_dispositivo',
                'Detectamos um novo login com o seu usuário em outro dispositivo. Por segurança, esta sessão será desconectada.',
            )

        agora = datetime.now(timezone.utc)
        if row.ultimo_acesso_em:
            ultimo = (
                row.ultimo_acesso_em.replace(tzinfo=timezone.utc)
                if row.ultimo_acesso_em.tzinfo is None
                else row.ultimo_acesso_em
            )
            if agora - ultimo > timedelta(minutes=INATIVIDADE_MAXIMA_MINUTOS):
                db.query(Usuario).filter(Usuario.id == usuario_id).update(
                    {'session_token': None}, synchronize_session=False
                )
                db.commit()
                session.clear()
                return (
                    False,
                    'inatividade',
                    'Sua sessão ficou inativa por 30 minutos sem atividade no sistema. Por medida de segurança, você será desconectado.',
                )

        return True, None, None