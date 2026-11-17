import os
import sys
import pandas as pd
from datetime import datetime
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from werkzeug.security import generate_password_hash

# Aponta para a raiz Analise_Hr e carrega o .env de lá
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

load_dotenv(os.path.join(ROOT_DIR, ".env"))

from app.services.conector_oracle import OracleConnector
from app.services.queries_senior import QUERY_ESTRUTURA_COLABORADORES
from app.models.models import Unidade, CentroCusto, Cargo, Colaborador, Usuario


class ETLEstruturaSenior:
    def __init__(self):
        self.oracle = OracleConnector()
        engine_pg = create_engine(os.getenv("DATABASE_URL"), pool_pre_ping=True)
        self.Session = sessionmaker(bind=engine_pg)

    def _garantir_usuario_root(self, session):
        """Lê ROOT_CRACHA e ROOT_SENHA do .env e cria/atualiza o usuário ROOT."""
        root_cracha = os.getenv("ROOT_CRACHA", "").strip()
        root_senha = os.getenv("ROOT_SENHA", "").strip()

        if not root_cracha or not root_senha:
            print("⚠️ [ROOT] Variáveis ROOT_CRACHA ou ROOT_SENHA não definidas no .env. Pulando criação.")
            return

        colab_root = session.query(Colaborador).filter_by(cracha=root_cracha).first()
        if not colab_root:
            print(f"⚠️ [ROOT] Colaborador com crachá '{root_cracha}' não encontrado na base.")
            return

        usuario_root = session.query(Usuario).filter_by(colaborador_id=colab_root.id).first()
        senha_criptografada = generate_password_hash(root_senha)

        if usuario_root:
            usuario_root.role = "ROOT"
            usuario_root.senha_hash = senha_criptografada
            usuario_root.ativo = True
            print(f"🔑 [ROOT] Usuário ROOT atualizado para: {colab_root.nome} (Crachá: {root_cracha})")
        else:
            novo_root = Usuario(
                colaborador_id=colab_root.id,
                senha_hash=senha_criptografada,
                role="ROOT",
                ativo=True,
            )
            session.add(novo_root)
            print(f"🔑 [ROOT] Usuário ROOT criado com sucesso: {colab_root.nome} (Crachá: {root_cracha})")

    def executar(self):
        inicio = datetime.now()
        print(f"🚀 [ETL ESTRUTURA] Iniciando carga às {inicio.strftime('%H:%M:%S')}...")

        if not self.oracle.conectar():
            raise RuntimeError("Falha ao conectar no Oracle Senior.")

        df = self.oracle.executar_query(QUERY_ESTRUTURA_COLABORADORES)
        self.oracle.fechar_conexao()

        if df.empty:
            print("⚠️ Nenhum colaborador retornado do Senior.")
            return

        df.columns = [str(c).lower().strip() for c in df.columns]
        df["data_nascimento"] = pd.to_datetime(df["data_nascimento"], errors="coerce").dt.date

        session = self.Session()
        try:
            # 1. UNIDADES
            map_unidades = {u.codigo_unidade: u for u in session.query(Unidade).all()}
            for _, row in df[["codigo_unidade", "nome_unidade"]].drop_duplicates().dropna().iterrows():
                cod = str(row["codigo_unidade"]).strip()
                nome = str(row["nome_unidade"]).strip()
                if cod not in map_unidades:
                    u = Unidade(codigo_unidade=cod, nome=nome, ativo=True)
                    session.add(u)
                    map_unidades[cod] = u
                else:
                    map_unidades[cod].nome = nome
            session.flush()

            # 2. CENTROS DE CUSTO
            map_ccs = {cc.codigo_cc: cc for cc in session.query(CentroCusto).all()}
            for _, row in df[["codigo_cc", "nome_cc", "codigo_unidade"]].drop_duplicates(subset=["codigo_cc"]).dropna().iterrows():
                cod_cc = str(row["codigo_cc"]).strip()
                nome_cc = str(row["nome_cc"]).strip()
                unidade_obj = map_unidades.get(str(row["codigo_unidade"]).strip())
                if not unidade_obj:
                    continue
                if cod_cc not in map_ccs:
                    cc = CentroCusto(codigo_cc=cod_cc, nome=nome_cc, unidade_id=unidade_obj.id, ativo=True)
                    session.add(cc)
                    map_ccs[cod_cc] = cc
                else:
                    map_ccs[cod_cc].nome = nome_cc
                    map_ccs[cod_cc].unidade_id = unidade_obj.id
            session.flush()

            # 3. CARGOS
            map_cargos = {c.codigo_cargo: c for c in session.query(Cargo).all()}
            for _, row in df[["codigo_cargo", "titulo_cargo"]].drop_duplicates(subset=["codigo_cargo"]).dropna().iterrows():
                cod_car = str(row["codigo_cargo"]).strip()
                titulo = str(row["titulo_cargo"]).strip()
                if cod_car not in map_cargos:
                    car = Cargo(codigo_cargo=cod_car, titulo=titulo)
                    session.add(car)
                    map_cargos[cod_car] = car
                else:
                    map_cargos[cod_car].titulo = titulo
            session.flush()

            # 4. COLABORADORES (Upsert por CPF)
            colabs_banco = {c.cpf: c for c in session.query(Colaborador).all()}
            cpfs_ativos_senior = set()
            inseridos, atualizados = 0, 0

            for _, row in df.drop_duplicates(subset=["cpf"]).iterrows():
                cpf = str(row["cpf"]).strip().zfill(11) if pd.notna(row["cpf"]) else None
                cracha = str(row["cracha"]).strip() if pd.notna(row["cracha"]) else None
                dt_nasc = row["data_nascimento"]
                cc_obj = map_ccs.get(str(row["codigo_cc"]).strip())
                cargo_obj = map_cargos.get(str(row["codigo_cargo"]).strip())

                if not cpf or not cracha or pd.isna(dt_nasc) or not cc_obj or not cargo_obj:
                    continue

                email_val = str(row["email"]).strip().lower() if pd.notna(row["email"]) and str(row["email"]).strip() else None
                nome_val = str(row["nome"]).strip()
                cpfs_ativos_senior.add(cpf)

                if cpf in colabs_banco:
                    c = colabs_banco[cpf]
                    c.cracha = cracha
                    c.nome = nome_val
                    c.data_nascimento = dt_nasc
                    c.email = email_val or c.email
                    c.cargo_id = cargo_obj.id
                    c.centro_custo_id = cc_obj.id
                    c.ativo = True
                    atualizados += 1
                else:
                    novo = Colaborador(
                        cracha=cracha,
                        nome=nome_val,
                        cpf=cpf,
                        data_nascimento=dt_nasc,
                        email=email_val,
                        cargo_id=cargo_obj.id,
                        centro_custo_id=cc_obj.id,
                        ativo=True,
                    )
                    session.add(novo)
                    inseridos += 1

            # Inativa quem saiu da base ativa do Senior
            inativados = 0
            for cpf, colab in colabs_banco.items():
                if cpf not in cpfs_ativos_senior and colab.ativo:
                    colab.ativo = False
                    inativados += 1

            session.flush()

            # 5. GARANTE USUÁRIO ROOT DO .ENV
            self._garantir_usuario_root(session)

            session.commit()
            duracao = (datetime.now() - inicio).total_seconds()
            print(f"✅ [ETL ESTRUTURA] Concluído em {duracao:.2f}s | Inseridos: {inseridos} | Atualizados: {atualizados} | Inativados: {inativados}")

        except Exception as e:
            session.rollback()
            print(f"❌ [ETL ESTRUTURA] Erro na carga: {e}")
            raise
        finally:
            session.close()


if __name__ == "__main__":
    ETLEstruturaSenior().executar()