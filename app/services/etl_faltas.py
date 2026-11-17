import os
import sys
import pandas as pd
from datetime import datetime, timedelta
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Aponta para a raiz Analise_Hr e carrega o .env de lá
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

load_dotenv(os.path.join(ROOT_DIR, ".env"))

from app.services.conector_oracle import OracleConnector
from app.services.queries_senior import montar_query_faltas
from app.models.models import Colaborador, CentroCusto, OcorrenciaFalta


class ETLFaltasDiario:
    def __init__(self, dias_retroativos: int = 15):
        self.dias_retroativos = dias_retroativos
        self.oracle = OracleConnector()
        engine_pg = create_engine(os.getenv("DATABASE_URL"), pool_pre_ping=True)
        self.Session = sessionmaker(bind=engine_pg)

    def executar(self):
        inicio = datetime.now()
        print(f"🚀 [ETL FALTAS] Buscando faltas dos últimos {self.dias_retroativos} dias (até ontem)...")

        if not self.oracle.conectar():
            raise RuntimeError("Falha ao conectar no Oracle Senior.")

        query = montar_query_faltas(self.dias_retroativos)
        df = self.oracle.executar_query(query)
        self.oracle.fechar_conexao()

        session = self.Session()
        try:
            hoje = datetime.now().date()
            data_inicio_janela = hoje - timedelta(days=self.dias_retroativos)

            map_colabs = {c.cpf: c for c in session.query(Colaborador).all() if c.cpf}
            map_ccs = {cc.codigo_cc: cc.id for cc in session.query(CentroCusto).all()}

            # Mapeia ocorrências já existentes no PostgreSQL dentro da janela
            ocorrencias_banco = {
                (o.colaborador_id, o.data_ocorrencia): o
                for o in session.query(OcorrenciaFalta)
                .filter(OcorrenciaFalta.data_ocorrencia >= data_inicio_janela)
                .all()
            }

            chaves_senior = set()
            inseridas = 0

            if not df.empty:
                df.columns = [str(c).lower().strip() for c in df.columns]
                df["data_ocorrencia"] = pd.to_datetime(df["data_ocorrencia"], errors="coerce").dt.date
                df = df.drop_duplicates(subset=["cpf", "data_ocorrencia"])

                for _, row in df.iterrows():
                    cpf = str(row["cpf"]).strip().zfill(11) if pd.notna(row["cpf"]) else None
                    dt_falta = row["data_ocorrencia"]
                    cod_cc = str(row["codigo_cc"]).strip() if pd.notna(row["codigo_cc"]) else None

                    # Trava extra de segurança no Python: nunca importa hoje ou futuro
                    if not cpf or pd.isna(dt_falta) or dt_falta >= hoje:
                        continue

                    colab = map_colabs.get(cpf)
                    if not colab:
                        continue

                    cc_id = map_ccs.get(cod_cc, colab.centro_custo_id)
                    chave = (colab.id, dt_falta)
                    chaves_senior.add(chave)

                    if chave not in ocorrencias_banco:
                        nova = OcorrenciaFalta(
                            colaborador_id=colab.id,
                            centro_custo_id=cc_id,
                            data_ocorrencia=dt_falta,
                            status="PENDENTE",
                        )
                        session.add(nova)
                        ocorrencias_banco[chave] = nova
                        inseridas += 1

            # Se alguma falta PENDENTE na janela foi abonada/removida no Senior, limpa do banco
            # (Nunca apaga ocorrências com status == 'ANALISADA')
            abonadas_removidas = 0
            for chave, ocorr in ocorrencias_banco.items():
                if ocorr.status == "PENDENTE" and chave not in chaves_senior:
                    session.delete(ocorr)
                    abonadas_removidas += 1

            session.commit()
            duracao = (datetime.now() - inicio).total_seconds()
            print(f"✅ [ETL FALTAS] Concluído em {duracao:.2f}s | Novas: {inseridas} | Abonadas/Removidas: {abonadas_removidas}")

        except Exception as e:
            session.rollback()
            print(f"❌ [ETL FALTAS] Erro na carga: {e}")
            raise
        finally:
            session.close()


if __name__ == "__main__":
    ETLFaltasDiario(dias_retroativos=15).executar()