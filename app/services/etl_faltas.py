import os
import sys
import pandas as pd
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.dialects.postgresql import insert as pg_insert

# Aponta para a raiz Analise_Hr e carrega o .env de lá
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

load_dotenv(os.path.join(ROOT_DIR, ".env"))

from app.services.conector_oracle import OracleConnector
from app.services.queries_senior import montar_query_faltas, CARGOS_REJEITADOS_LEGADO
from app.models.models import Colaborador, CentroCusto, Cargo, OcorrenciaFalta

FUSO_BRASIL = timezone(timedelta(hours=-3))


class ETLFaltasDiario:
    def __init__(self, dias_retroativos: int = 15):
        self.dias_retroativos = dias_retroativos
        self.oracle = OracleConnector()
        engine_pg = create_engine(os.getenv("DATABASE_URL"), pool_pre_ping=True)
        self.Session = sessionmaker(bind=engine_pg)

    def executar(self):
        inicio = datetime.now(FUSO_BRASIL)
        print(f"🚀 [ETL FALTAS] Buscando faltas dos últimos {self.dias_retroativos} dias (até ontem)...")

        if not self.oracle.conectar():
            raise RuntimeError("Falha ao conectar no Oracle Senior.")

        query = montar_query_faltas(self.dias_retroativos)
        df = self.oracle.executar_query(query)
        self.oracle.fechar_conexao()

        if df.empty:
            print("ℹ️ [ETL FALTAS] Nenhuma falta retornada do Oracle na janela consultada.")
            return

        session = self.Session()
        try:
            with session.no_autoflush:
                # Alinha a data de corte com o horário de Brasília (-03:00)
                hoje_br = datetime.now(FUSO_BRASIL).date()

                cargos_rejeitados_ids = {
                    c.id
                    for c in session.query(Cargo.id, Cargo.codigo_cargo).all()
                    if str(c.codigo_cargo or "").strip() in CARGOS_REJEITADOS_LEGADO
                }

                map_colabs = {
                    str(c.cpf).strip().zfill(11): c
                    for c in session.query(Colaborador).all()
                    if c.cpf and c.cargo_id not in cargos_rejeitados_ids
                }
                map_ccs = {
                    str(cc.codigo_cc).strip(): cc.id
                    for cc in session.query(CentroCusto).all()
                    if cc.codigo_cc
                }

                df.columns = [str(c).lower().strip() for c in df.columns]
                df["data_ocorrencia"] = pd.to_datetime(df["data_ocorrencia"], errors="coerce").dt.date
                df["cpf_limpo"] = df["cpf"].apply(
                    lambda x: "".join(filter(str.isdigit, str(x))).zfill(11)
                    if pd.notna(x) and "".join(filter(str.isdigit, str(x)))
                    else None
                )
                df = df.dropna(subset=["cpf_limpo", "data_ocorrencia"])
                df = df.drop_duplicates(subset=["cpf_limpo", "data_ocorrencia"])

                registros_para_inserir = []
                agora_utc = datetime.now(timezone.utc)
                sem_colaborador = 0

                for _, row in df.iterrows():
                    cpf = row["cpf_limpo"]
                    dt_falta = row["data_ocorrencia"]
                    cod_cc = str(row["codigo_cc"]).strip() if pd.notna(row["codigo_cc"]) else None

                    # Nunca importa ocorrências do dia corrente ou futuras
                    if dt_falta >= hoje_br:
                        continue

                    colab = map_colabs.get(cpf)
                    if not colab:
                        sem_colaborador += 1
                        continue

                    cc_id = map_ccs.get(cod_cc, colab.centro_custo_id)
                    registros_para_inserir.append({
                        "colaborador_id": colab.id,
                        "centro_custo_id": cc_id,
                        "data_ocorrencia": dt_falta,
                        "status": "PENDENTE",
                        "importado_em": agora_utc,
                    })

                inseridas = 0
                if registros_para_inserir:
                    stmt = (
                        pg_insert(OcorrenciaFalta.__table__)
                        .values(registros_para_inserir)
                        .on_conflict_do_nothing(constraint="uq_colaborador_data_falta")
                    )
                    res_ins = session.execute(stmt)
                    inseridas = res_ins.rowcount or 0

                ja_existentes = len(registros_para_inserir) - inseridas

            session.commit()
            duracao = (datetime.now(FUSO_BRASIL) - inicio).total_seconds()
            print(
                f"✅ [ETL FALTAS] Concluído em {duracao:.2f}s | "
                f"Novas inseridas: {inseridas} | Já existentes (mantidas): {ja_existentes} | "
                f"Ignoradas (sem cadastro ativo): {sem_colaborador}"
            )

        except Exception as e:
            session.rollback()
            print(f"❌ [ETL FALTAS] Erro na carga: {e}")
            raise
        finally:
            session.close()


if __name__ == "__main__":
    ETLFaltasDiario(dias_retroativos=15).executar()