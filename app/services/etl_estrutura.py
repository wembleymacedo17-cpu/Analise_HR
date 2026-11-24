import os
import sys
import pandas as pd
from datetime import datetime
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.dialects.postgresql import insert as pg_insert
from werkzeug.security import check_password_hash, generate_password_hash




ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

load_dotenv(os.path.join(ROOT_DIR, ".env"))

from app.services.conector_oracle import OracleConnector
from app.services.queries_senior import QUERY_ESTRUTURA_COLABORADORES, CARGOS_REJEITADOS_LEGADO
from app.models.models import Unidade, CentroCusto, Cargo, Colaborador, Usuario


def _normalizar_sexo(valor) -> str | None:
    if valor is None or pd.isna(valor):
        return None
    s = str(valor).strip().upper()
    if s in ("M", "MASCULINO", "1"):
        return "M"
    if s in ("F", "FEMININO", "2"):
        return "F"
    return s[:10] if s else None


def _limpar_cpf(valor) -> str | None:
    if valor is None or pd.isna(valor):
        return None
    digitos = "".join(filter(str.isdigit, str(valor)))
    return digitos.zfill(11) if digitos else None


class ETLEstruturaSenior:
    def __init__(self):
        self.oracle = OracleConnector()
        engine_pg = create_engine(os.getenv("DATABASE_URL"), pool_pre_ping=True)
        self.Session = sessionmaker(bind=engine_pg)

    def _garantir_usuario_root(self, session):
        

        root_cracha = os.getenv("ROOT_CRACHA", "").strip().strip("'\"")
        root_senha = os.getenv("ROOT_SENHA", "").strip().strip("'\"")

        if not root_cracha or not root_senha:
            print("⚠️ [ROOT] Variáveis ROOT_CRACHA ou ROOT_SENHA não definidas no .env. Pulando criação.")
            return

        colab_root = session.query(Colaborador).filter_by(cracha=root_cracha).first()
        if not colab_root:
            print(f"⚠️ [ROOT] Colaborador com crachá '{root_cracha}' não encontrado na base.")
            return

        usuario_root = session.query(Usuario).filter_by(colaborador_id=colab_root.id).first()

        if usuario_root:
            usuario_root.role = "ROOT"
            usuario_root.ativo = True
            # Só atualiza o hash se ainda não tiver senha ou se a senha atual não bater com o .env
            if not usuario_root.senha_hash or not check_password_hash(usuario_root.senha_hash, root_senha):
                usuario_root.senha_hash = generate_password_hash(root_senha)
                print(f"🔑 [ROOT] Senha do usuário ROOT sincronizada com .env para: {colab_root.nome} (Crachá: {root_cracha})")
            else:
                print(f"🔑 [ROOT] Usuário ROOT verificado: {colab_root.nome} (Crachá: {root_cracha})")
        else:
            novo_root = Usuario(
                colaborador_id=colab_root.id,
                senha_hash=generate_password_hash(root_senha),
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

        df["codigo_cargo_limpo"] = df["codigo_cargo"].astype(str).str.strip()
        df = df[~df["codigo_cargo_limpo"].isin(CARGOS_REJEITADOS_LEGADO)]

        if df.empty:
            print("⚠️ Nenhum colaborador elegível após filtrar CARGOS_REJEITADOS_LEGADO.")
            return

        session = self.Session()
        try:
            with session.no_autoflush:
                # 1. UNIDADES
                map_unidades = {
                    str(u.codigo_unidade).strip(): u
                    for u in session.query(Unidade).all()
                    if u.codigo_unidade
                }
                for _, row in df[["codigo_unidade", "nome_unidade"]].dropna().iterrows():
                    cod = str(row["codigo_unidade"]).strip()
                    nome = str(row["nome_unidade"]).strip()
                    if not cod:
                        continue
                    if cod not in map_unidades:
                        u = Unidade(codigo_unidade=cod, nome=nome, ativo=True)
                        session.add(u)
                        map_unidades[cod] = u
                    elif map_unidades[cod].nome != nome:
                        map_unidades[cod].nome = nome
                session.flush()

                # 2. CENTROS DE CUSTO
                map_ccs = {
                    str(cc.codigo_cc).strip(): cc
                    for cc in session.query(CentroCusto).all()
                    if cc.codigo_cc
                }
                for _, row in df[["codigo_cc", "nome_cc", "codigo_unidade"]].dropna().iterrows():
                    cod_cc = str(row["codigo_cc"]).strip()
                    nome_cc = str(row["nome_cc"]).strip()
                    unidade_obj = map_unidades.get(str(row["codigo_unidade"]).strip())
                    if not cod_cc or not unidade_obj:
                        continue
                    if cod_cc not in map_ccs:
                        cc = CentroCusto(codigo_cc=cod_cc, nome=nome_cc, unidade_id=unidade_obj.id, ativo=True)
                        session.add(cc)
                        map_ccs[cod_cc] = cc
                    else:
                        if map_ccs[cod_cc].nome != nome_cc:
                            map_ccs[cod_cc].nome = nome_cc
                        if map_ccs[cod_cc].unidade_id != unidade_obj.id:
                            map_ccs[cod_cc].unidade_id = unidade_obj.id
                session.flush()

                # 3. CARGOS
                cargos_upsert = {}
                for _, row in df[["codigo_cargo_limpo", "titulo_cargo"]].dropna().iterrows():
                    cod_car = str(row["codigo_cargo_limpo"]).strip()
                    if not cod_car or cod_car in CARGOS_REJEITADOS_LEGADO:
                        continue
                    cargos_upsert[cod_car] = str(row["titulo_cargo"]).strip()

                if cargos_upsert:
                    valores_cargos = [{"codigo_cargo": k, "titulo": v} for k, v in cargos_upsert.items()]
                    stmt_cargo = pg_insert(Cargo.__table__).values(valores_cargos)
                    stmt_cargo = stmt_cargo.on_conflict_do_update(
                        index_elements=["codigo_cargo"],
                        set_={"titulo": stmt_cargo.excluded.titulo},
                    )
                    session.execute(stmt_cargo)
                    session.flush()

                map_cargos = {
                    str(c.codigo_cargo).strip(): c
                    for c in session.query(Cargo).all()
                    if c.codigo_cargo
                }

                # 4. COLABORADORES (Diff real)
                todos_colabs = session.query(Colaborador).all()
                colabs_por_cpf = {}
                colabs_por_cracha = {}
                for c in todos_colabs:
                    cpf_norm = _limpar_cpf(c.cpf)
                    if cpf_norm:
                        colabs_por_cpf[cpf_norm] = c
                    if c.cracha:
                        colabs_por_cracha[str(c.cracha).strip()] = c

                df["cpf_limpo"] = df["cpf"].apply(_limpar_cpf)
                df_colabs = df.dropna(subset=["cpf_limpo"]).drop_duplicates(subset=["cpf_limpo"])

                cpfs_ativos_senior = set()
                inseridos, atualizados, inalterados = 0, 0, 0

                for _, row in df_colabs.iterrows():
                    cod_car = str(row["codigo_cargo_limpo"]).strip()
                    if cod_car in CARGOS_REJEITADOS_LEGADO:
                        continue

                    cpf = row["cpf_limpo"]
                    cracha = str(row["cracha"]).strip() if pd.notna(row["cracha"]) else None
                    dt_nasc = row["data_nascimento"]
                    cc_obj = map_ccs.get(str(row["codigo_cc"]).strip())
                    cargo_obj = map_cargos.get(cod_car)

                    if not cpf or not cracha or pd.isna(dt_nasc) or not cc_obj or not cargo_obj:
                        continue

                    sexo_val = _normalizar_sexo(row["sexo"]) if "sexo" in row else None
                    email_val = str(row["email"]).strip().lower() if pd.notna(row["email"]) and str(row["email"]).strip() else None
                    nome_val = str(row["nome"]).strip()
                    cpfs_ativos_senior.add(cpf)

                    colab_existente = colabs_por_cpf.get(cpf) or colabs_por_cracha.get(cracha)

                    if colab_existente:
                        novo_sexo = sexo_val or colab_existente.sexo
                        novo_email = email_val or colab_existente.email

                        mudou = (
                            colab_existente.cpf != cpf
                            or str(colab_existente.cracha).strip() != cracha
                            or str(colab_existente.nome).strip() != nome_val
                            or colab_existente.sexo != novo_sexo
                            or colab_existente.data_nascimento != dt_nasc
                            or (colab_existente.email or None) != novo_email
                            or colab_existente.cargo_id != cargo_obj.id
                            or colab_existente.centro_custo_id != cc_obj.id
                            or colab_existente.ativo is not True
                        )

                        colabs_por_cpf[cpf] = colab_existente
                        colabs_por_cracha[cracha] = colab_existente

                        if mudou:
                            colab_existente.cpf = cpf
                            colab_existente.cracha = cracha
                            colab_existente.nome = nome_val
                            colab_existente.sexo = novo_sexo
                            colab_existente.data_nascimento = dt_nasc
                            colab_existente.email = novo_email
                            colab_existente.cargo_id = cargo_obj.id
                            colab_existente.centro_custo_id = cc_obj.id
                            colab_existente.ativo = True
                            atualizados += 1
                        else:
                            inalterados += 1
                    else:
                        novo = Colaborador(
                            cracha=cracha,
                            nome=nome_val,
                            sexo=sexo_val,
                            cpf=cpf,
                            data_nascimento=dt_nasc,
                            email=email_val,
                            cargo_id=cargo_obj.id,
                            centro_custo_id=cc_obj.id,
                            ativo=True,
                        )
                        session.add(novo)
                        colabs_por_cpf[cpf] = novo
                        colabs_por_cracha[cracha] = novo
                        inseridos += 1

                inativados = 0
                for cpf, colab in colabs_por_cpf.items():
                    if cpf not in cpfs_ativos_senior and colab.ativo:
                        colab.ativo = False
                        inativados += 1

                session.flush()

                # 5. GARANTE USUÁRIO ROOT DO .ENV SEM SOBRESCREVER SENHA ALTERADA
                self._garantir_usuario_root(session)

            session.commit()
            duracao = (datetime.now() - inicio).total_seconds()
            print(
                f"✅ [ETL ESTRUTURA] Concluído em {duracao:.2f}s | "
                f"Inseridos: {inseridos} | Atualizados: {atualizados} | "
                f"Inalterados: {inalterados} | Inativados: {inativados}"
            )

        except Exception as e:
            session.rollback()
            print(f"❌ [ETL ESTRUTURA] Erro na carga: {e}")
            raise
        finally:
            session.close()


if __name__ == "__main__":
    ETLEstruturaSenior().executar()