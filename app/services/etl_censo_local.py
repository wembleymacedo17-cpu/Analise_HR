import os
import glob
import time
import shutil
import tempfile
from datetime import datetime, timezone
import pandas as pd
import requests
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.dialects.postgresql import insert as pg_insert

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
load_dotenv(os.path.join(ROOT_DIR, ".env"))

PASTA_CENSO = os.getenv("CENSO_PASTA_ORIGEM", r"E:\Progress10\TEMP").strip()
# Travado exclusivamente no CENSO_FUNFARME para nunca abrir CENSO_COMPLETO
PADRAO_ARQUIVO = os.getenv("CENSO_PADRAO_ARQUIVO", "CENSO_FUNFARME*.xls*").strip()
API_URL_CENSO = os.getenv("CENSO_API_URL", "").strip()
API_KEY_CENSO = os.getenv("CENSO_SYNC_KEY", "").strip().strip("'\"")
INTERVALO_MINUTOS = int(os.getenv("CENSO_INTERVALO_MINUTOS", "30"))


def localizar_planilha_censo_funfarme(pasta: str, padrao: str) -> str:
    if not os.path.isdir(pasta):
        raise FileNotFoundError(f"Diretório não encontrado: {pasta}")

    # Prioriza exatamente CENSO_FUNFARME.XLSX / CENSO_FUNFARME.xlsx
    for nome_exato in ("CENSO_FUNFARME.XLSX", "CENSO_FUNFARME.xlsx", "CENSO_FUNFARME.xls"):
        caminho_exato = os.path.join(pasta, nome_exato)
        if os.path.isfile(caminho_exato):
            return caminho_exato

    # Fallback apenas para arquivos que comecem com CENSO_FUNFARME (nunca CENSO_COMPLETO)
    candidatos = [
        arq for arq in glob.glob(os.path.join(pasta, padrao))
        if not os.path.basename(arq).startswith("~$")
        and "COMPLETO" not in os.path.basename(arq).upper()
    ]

    if not candidatos:
        raise FileNotFoundError(f"Planilha CENSO_FUNFARME não encontrada em {pasta}")

    return max(candidatos, key=os.path.getmtime)


def processar_planilha_censo(caminho_original: str) -> tuple[str, list[dict]]:
    """
    Copia CENSO_FUNFARME.XLSX para temp, localiza o cabeçalho ('Unidade de internação')
    e conta exatamente quantas linhas existem por unidade.
    """
    nome_arquivo = os.path.basename(caminho_original)
    fd, caminho_temp = tempfile.mkstemp(suffix=os.path.splitext(nome_arquivo)[1])
    os.close(fd)

    try:
        shutil.copy2(caminho_original, caminho_temp)
        df_bruto = pd.read_excel(caminho_temp, sheet_name=0, header=None)
    finally:
        if os.path.exists(caminho_temp):
            os.remove(caminho_temp)

    linha_cabecalho = None
    for idx in range(min(25, len(df_bruto))):
        valores_linha = [
            str(v).replace("\xa0", " ").strip().lower()
            for v in df_bruto.iloc[idx].tolist()
            if pd.notna(v)
        ]
        if any("unidade de intern" in val or val == "unidade" for val in valores_linha):
            linha_cabecalho = idx
            break

    if linha_cabecalho is None:
        raise ValueError(f"Coluna 'Unidade de internação' não encontrada em '{nome_arquivo}'.")

    colunas = [
        str(c).replace("\xa0", " ").strip() if pd.notna(c) else f"col_{i}"
        for i, c in enumerate(df_bruto.iloc[linha_cabecalho].tolist())
    ]
    df = df_bruto.iloc[linha_cabecalho + 1 :].copy()
    df.columns = colunas

    col_unidade = next((c for c in df.columns if "unidade de intern" in c.lower() or c.lower() == "unidade"), None)
    if not col_unidade:
        raise ValueError(f"Coluna 'Unidade de internação' não identificada em '{nome_arquivo}'.")

    serie_unidades = (
        df[col_unidade]
        .dropna()
        .astype(str)
        .str.replace("\xa0", " ", regex=False)
        .str.strip()
    )
    serie_unidades = serie_unidades[
        (serie_unidades != "")
        & (serie_unidades.str.lower() != "unidade de internação")
        & (~serie_unidades.str.lower().str.startswith("total"))
    ]

    contagem = serie_unidades.value_counts().sort_index()
    registros = [
        {"nome_unidade": str(unidade), "qtd_internacao": int(qtd)}
        for unidade, qtd in contagem.items()
    ]
    return nome_arquivo, registros


def persistir_censo_no_banco(db, itens: list[dict]) -> dict:
    """Garante a existência da tabela e grava nome_unidade + qtd_internacao no PostgreSQL."""
    from app.models.models import Base, CensoInternacaoUnidade

    # Garante que censo_internacao_unidades (e programacoes_assistenciais) existam no banco
    bind_engine = db.get_bind()
    if bind_engine is not None:
        Base.metadata.create_all(bind=bind_engine)

    agora_utc = datetime.now(timezone.utc)
    mapa_unidades = {}
    for item in itens:
        nome = str(item.get("nome_unidade") or "").replace("\xa0", " ").strip()
        qtd = int(item.get("qtd_internacao") or 0)
        if nome:
            mapa_unidades[nome] = mapa_unidades.get(nome, 0) + qtd

    nomes_atuais = set(mapa_unidades.keys())

    if nomes_atuais:
        db.query(CensoInternacaoUnidade).filter(
            CensoInternacaoUnidade.nome_unidade.notin_(list(nomes_atuais))
        ).update(
            {"qtd_internacao": 0, "atualizado_em": agora_utc},
            synchronize_session=False,
        )

    if mapa_unidades:
        valores_upsert = [
            {
                "nome_unidade": nome,
                "qtd_internacao": qtd,
                "atualizado_em": agora_utc,
            }
            for nome, qtd in mapa_unidades.items()
        ]
        stmt = pg_insert(CensoInternacaoUnidade.__table__).values(valores_upsert)
        stmt = stmt.on_conflict_do_update(
            index_elements=["nome_unidade"],
            set_={
                "qtd_internacao": stmt.excluded.qtd_internacao,
                "atualizado_em": stmt.excluded.atualizado_em,
            },
        )
        db.execute(stmt)

    db.commit()
    return {
        "sucesso": True,
        "unidades_atualizadas": len(mapa_unidades),
        "total_internados": sum(mapa_unidades.values()),
    }


def executar_sincronizacao_censo() -> dict:
    caminho = localizar_planilha_censo_funfarme(PASTA_CENSO, PADRAO_ARQUIVO)
    nome_arq, resumo_unidades = processar_planilha_censo(caminho)
    total_pacientes = sum(u["qtd_internacao"] for u in resumo_unidades)
    print(f"📄 [CENSO] Lido '{nome_arq}' -> {total_pacientes} internados em {len(resumo_unidades)} unidades.")

    if API_URL_CENSO and "127.0.0.1" not in API_URL_CENSO and "localhost" not in API_URL_CENSO:
        headers = {"Content-Type": "application/json"}
        if API_KEY_CENSO:
            headers["X-API-KEY"] = API_KEY_CENSO
        resp = requests.post(
            API_URL_CENSO,
            json={"arquivo": nome_arq, "unidades": resumo_unidades},
            headers=headers,
            timeout=25,
        )
        dados_resp = resp.json()
        if not resp.ok or not dados_resp.get("sucesso"):
            raise RuntimeError(f"Falha na API remota ({resp.status_code}): {dados_resp.get('mensagem', resp.text)}")
        print(f"✅ [CENSO] Sincronizado na API remota: {dados_resp}")
        return dados_resp

    engine_pg = create_engine(os.getenv("DATABASE_URL"), pool_pre_ping=True)
    SessionLocal = sessionmaker(bind=engine_pg)
    session = SessionLocal()
    try:
        res = persistir_censo_no_banco(session, resumo_unidades)
        print(
            f"✅ [CENSO] Gravado no banco: {res['unidades_atualizadas']} unidades | "
            f"{res['total_internados']} internados totais."
        )
        return res
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def iniciar_daemon_censo_30min():
    print(f"🏥 Iniciando monitor do Censo em '{PASTA_CENSO}' (ciclo de {INTERVALO_MINUTOS} min)...")
    while True:
        try:
            executar_sincronizacao_censo()
        except Exception as e:
            print(f"❌ Erro no job do censo: {e}")
        time.sleep(INTERVALO_MINUTOS * 60)