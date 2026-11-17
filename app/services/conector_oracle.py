# conector_oracle.py
import os
from typing import Optional
import pandas as pd
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.engine import URL

# Localiza a raiz do projeto (Analise_Hr) e carrega o .env de lá
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
load_dotenv(os.path.join(ROOT_DIR, ".env"))


class OracleConnector:
    def __init__(self):
        self.user = os.getenv("ORACLE_USER")
        self.password = os.getenv("ORACLE_PASSWORD")
        self.host = os.getenv("ORACLE_HOST")
        port_env = os.getenv("ORACLE_PORT")
        self.port = int(port_env) if port_env else 1521
        self.service_name = os.getenv("ORACLE_SERVICE_NAME")
        self.schema = os.getenv("ORACLE_SCHEMA")
        self.engine = None

    def conectar(self):
        try:
            connection_url = URL.create(
                "oracle+oracledb",
                username=self.user,
                password=self.password,
                host=self.host,
                port=self.port,
                query={"service_name": self.service_name},
            )
            self.engine = create_engine(connection_url)

            with self.engine.connect():
                pass

            print("✅ Conexão com Oracle realizada com sucesso!")
            return True

        except Exception as e:
            print(f"❌ Erro ao conectar no Oracle: {e}")
            return False

    def executar_query(self, query: str, chunksize: Optional[int] = None) -> pd.DataFrame:
        if not self.engine:
            print("⚠️ Você precisa chamar .conectar() primeiro!")
            return pd.DataFrame()

        try:
            print("🔄 Executando query...")
            df = pd.read_sql(query, self.engine, chunksize=chunksize)

            if isinstance(df, pd.DataFrame):
                df_final = df
            else:
                df_final = pd.concat(list(df), ignore_index=True)

            print(f"✅ Query executada com sucesso! Total de linhas: {len(df_final)}")
            return df_final

        except Exception as e:
            print(f"❌ Erro ao executar query: {e}")
            return pd.DataFrame()

    def fechar_conexao(self):
        if self.engine:
            self.engine.dispose()
            print("🔌 Conexão encerrada.")