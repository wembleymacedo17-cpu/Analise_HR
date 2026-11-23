import os
from flask import Flask, render_template, session, redirect, url_for, request, g, send_file
from dotenv import load_dotenv
from werkzeug.middleware.proxy_fix import ProxyFix
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.services.cookie_service import CookieService

raiz_projeto = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
env_path = os.path.join(raiz_projeto, '.env')

if os.path.exists(env_path):
    load_dotenv(env_path)
else:
    load_dotenv()

database_url = os.getenv('DATABASE_URL')
if not database_url:
    raise ValueError(f"DATABASE_URL não configurada em: {env_path}")

if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

engine = create_engine(
    database_url,
    pool_size=int(os.getenv('DB_POOL_SIZE', 5)),
    max_overflow=int(os.getenv('DB_MAX_OVERFLOW', 5)),
    pool_recycle=300,
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(bind=engine)


def get_db():
    if 'db' not in g:
        g.db = SessionLocal()
    return g.db


def create_app():
    base_dir = os.path.abspath(os.path.dirname(__file__))
    template_dir = os.path.join(base_dir, 'views', 'html')
    static_dir = os.path.join(base_dir, 'views')

    app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)

    CookieService.configurar_seguranca_sessao(app)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    @app.before_request
    def verificar_seguranca_sessao():
        rotas_publicas = {
            '/login', '/primeiro-acesso', '/api/login',
            '/api/primeiro-acesso', '/api/verificar-sessao', '/logo-funfarme'
        }
        if request.path.startswith('/static/') or request.path in rotas_publicas:
            return None

        if 'usuario_id' not in session:
            if request.path.startswith('/api/'):
                return {'sucesso': False, 'sessao_expirada': True, 'mensagem': 'Sessão encerrada.'}, 401
            return redirect(url_for('login_page'))

        db = get_db()
        valida, motivo, mensagem = CookieService.validar_sessao_unica_e_atividade(db)
        if not valida:
            if request.path.startswith('/api/'):
                return {
                    'sucesso': False,
                    'sessao_expirada': True,
                    'motivo': motivo,
                    'mensagem': mensagem,
                }, 401
            return redirect(url_for('login_page', motivo=motivo))

    @app.teardown_appcontext
    def fechar_sessao_db(exception=None):
        db = g.pop('db', None)
        if db is not None:
            db.close()

    @app.after_request
    def adicionar_cabecalhos_no_cache(response):
        if not request.path.startswith('/static/'):
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
        return response

    @app.route('/logo-funfarme')
    def logo_funfarme():
        img_dir = os.path.join(base_dir, 'views', 'img')
        if os.path.isdir(img_dir):
            for arquivo in os.listdir(img_dir):
                if arquivo.lower().startswith('logo_funfarme'):
                    return send_file(os.path.join(img_dir, arquivo))
        return '', 404

    # ==========================================================================
    # ROTAS DE PÁGINAS (VIEWS HTML)
    # ==========================================================================
    @app.route('/')
    def index():
        if 'usuario_id' not in session:
            return redirect(url_for('login_page'))
        return render_template(
            'index.html',
            usuario=session.get('usuario_nome'),
            cracha=session.get('cracha'),
            perfil=session.get('usuario_perfil')
        )

    @app.route('/login')
    def login_page():
        return render_template('login.html')

    @app.route('/primeiro-acesso')
    def primeiro_acesso_page():
        return render_template('primeiro_acesso.html')

    @app.route('/logout')
    def logout():
        db = get_db()
        resp = redirect(url_for('login_page'))
        return CookieService.encerrar_sessao(db=db, response=resp)

    @app.route('/convites')
    def convites_page():
        if session.get('usuario_perfil') != 'ROOT':
            return redirect(url_for('index'))
        return render_template('convites.html')

    @app.route('/dashboard')
    def dashboard_page():
        if session.get('usuario_perfil') != 'ROOT':
            return redirect(url_for('index'))
        return render_template('dashboard.html')

    from app.controllers.api_routes import api_bp
    app.register_blueprint(api_bp)

    return app

    