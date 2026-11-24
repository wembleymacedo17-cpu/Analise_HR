import os
import sys
import io
import json
import time
import threading
from collections import deque
from datetime import datetime, timedelta
from sqlalchemy import text

from app import get_db
from app.services.etl_estrutura import ETLEstruturaSenior
from app.services.etl_faltas import ETLFaltasDiario

DIR_SERVICES = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE_PATH = os.path.join(DIR_SERVICES, "agendamentos_config.json")
LOCK_FILE_PATH = os.path.join(DIR_SERVICES, ".scheduler.lock")

# Buffer circular de logs para o terminal web (últimas 400 linhas)
TERMINAL_LOGS = deque(maxlen=400)
_LOG_LOCK = threading.Lock()
_LOG_SEQ = 0
_SCHEDULER_INICIADO = False


def registrar_log(mensagem: str, nivel: str = "INFO", origem: str = "SYSTEM"):
    """Registra uma linha no terminal web e imprime no stdout."""
    global _LOG_SEQ
    ts = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    texto = str(mensagem).rstrip()
    if not texto:
        return
    with _LOG_LOCK:
        _LOG_SEQ += 1
        TERMINAL_LOGS.append({
            "id": _LOG_SEQ,
            "ts": ts,
            "nivel": nivel.upper(),
            "origem": origem.upper(),
            "mensagem": texto,
        })
    print(f"[{ts}] [{origem}] {texto}", flush=True)


class _StreamCaptor(io.TextIOBase):
    """Captura prints/logs durante a execução de um ETL e envia em tempo real ao terminal web."""
    def __init__(self, origem: str, original_stream):
        self.origem = origem
        self.original_stream = original_stream
        self._buffer = ""

    def write(self, s):
        if self.original_stream:
            self.original_stream.write(s)
        self._buffer += s
        while "\n" in self._buffer:
            linha, self._buffer = self._buffer.split("\n", 1)
            if linha.strip():
                nivel = "ERROR" if ("erro" in linha.lower() or "❌" in linha or "exception" in linha.lower()) else "INFO"
                registrar_log(linha, nivel=nivel, origem=self.origem)
        return len(s)

    def flush(self):
        if self._buffer.strip():
            registrar_log(self._buffer.strip(), nivel="INFO", origem=self.origem)
            self._buffer = ""
        if self.original_stream:
            self.original_stream.flush()


# =========================================================================
# TAREFAS DISPONÍVEIS NO ANALISE_HR
# =========================================================================
def _executar_com_captura(task_key: str, label: str, fn):
    if AGENDADORES[task_key]["executando"]:
        registrar_log(f"Tarefa '{label}' já está em execução. Ignorando disparo duplicado.", nivel="WARN", origem=task_key)
        return {"sucesso": False, "mensagem": f"{label} já está em execução."}

    AGENDADORES[task_key]["executando"] = True
    inicio = datetime.now()
    registrar_log(f"🚀 Iniciando {label}...", nivel="INFO", origem=task_key)

    old_stdout, old_stderr = sys.stdout, sys.stderr
    captor_out = _StreamCaptor(task_key, old_stdout)
    captor_err = _StreamCaptor(task_key, old_stderr)
    sys.stdout, sys.stderr = captor_out, captor_err

    try:
        fn()
        captor_out.flush()
        captor_err.flush()
        duracao = round((datetime.now() - inicio).total_seconds(), 2)
        AGENDADORES[task_key]["ultima_execucao"] = datetime.now()
        registrar_log(f"✅ {label} concluída com sucesso em {duracao}s.", nivel="SUCCESS", origem=task_key)
        return {"sucesso": True, "mensagem": f"{label} concluída em {duracao}s!"}
    except Exception as e:
        captor_out.flush()
        captor_err.flush()
        registrar_log(f"❌ Falha em {label}: {str(e)}", nivel="ERROR", origem=task_key)
        return {"sucesso": False, "mensagem": f"Erro em {label}: {str(e)}"}
    finally:
        sys.stdout, sys.stderr = old_stdout, old_stderr
        AGENDADORES[task_key]["executando"] = False


def executar_task_faltas():
    return _executar_com_captura(
        "faltas",
        "Carga Diária de Ocorrências (D-15)",
        lambda: ETLFaltasDiario(dias_retroativos=15).executar()
    )


def executar_task_estrutura():
    return _executar_com_captura(
        "estrutura",
        "Carga de Estrutura e Colaboradores",
        lambda: ETLEstruturaSenior().executar()
    )


MAPA_FUNCOES = {
    "faltas": executar_task_faltas,
    "estrutura": executar_task_estrutura,
}

AGENDADORES = {
    "faltas": {
        "nome": "Carga Diária (Ocorrências D-1)",
        "ativo": False,
        "executando": False,
        "intervalo_horas": 2.0,
        "proxima_execucao": None,
        "ultima_execucao": None,
        "thread": None,
    },
    "estrutura": {
        "nome": "Carga Semanal de Estrutura",
        "ativo": False,
        "executando": False,
        "intervalo_horas": 24.0,
        "proxima_execucao": None,
        "ultima_execucao": None,
        "thread": None,
    },
}


# =========================================================================
# PERSISTÊNCIA EM JSON + RECUPERAÇÃO AUTOMÁTICA PÓS-QUEDA (CATCH-UP)
# =========================================================================
def salvar_agendamentos_disco():
    dados = {}
    for task, info in AGENDADORES.items():
        dados[task] = {
            "ativo": info["ativo"],
            "intervalo_horas": info["intervalo_horas"],
            "proxima_execucao": info["proxima_execucao"].isoformat() if info["proxima_execucao"] else None,
            "ultima_execucao": info["ultima_execucao"].isoformat() if info["ultima_execucao"] else None,
        }
    try:
        os.makedirs(os.path.dirname(CONFIG_FILE_PATH), exist_ok=True)
        tmp_path = CONFIG_FILE_PATH + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(dados, f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, CONFIG_FILE_PATH)
    except Exception as e:
        registrar_log(f"Erro ao salvar agendamentos no disco: {e}", nivel="ERROR", origem="SCHEDULER")


def _loop_agendador_tarefa(task_name: str, recuperar_atrasada: bool = False):
    func_target = MAPA_FUNCOES.get(task_name)
    if not func_target:
        return

    # Se a aplicação caiu e o horário agendado passou durante a queda, executa imediatamente!
    if recuperar_atrasada and AGENDADORES[task_name]["ativo"]:
        registrar_log(
            f"🔄 [RECUPERAÇÃO AUTOMÁTICA] Horário vencido detectado para '{task_name}'. Executando agora...",
            nivel="WARN",
            origem="SCHEDULER"
        )
        func_target()
        agora_pos = datetime.now()
        nova_proxima = agora_pos + timedelta(hours=AGENDADORES[task_name]["intervalo_horas"])
        AGENDADORES[task_name]["proxima_execucao"] = nova_proxima
        salvar_agendamentos_disco()
        registrar_log(
            f"📅 Próxima execução de '{task_name}' reagendada para {nova_proxima.strftime('%d/%m/%Y %H:%M:%S')}.",
            nivel="INFO",
            origem="SCHEDULER"
        )

    while AGENDADORES[task_name]["ativo"]:
        agora = datetime.now()
        proxima = AGENDADORES[task_name]["proxima_execucao"]

        if proxima and agora >= proxima:
            registrar_log(f"⏰ Disparando rotina agendada '{task_name}'...", nivel="INFO", origem="SCHEDULER")
            func_target()
            agora_pos = datetime.now()
            nova_proxima = agora_pos + timedelta(hours=AGENDADORES[task_name]["intervalo_horas"])
            AGENDADORES[task_name]["proxima_execucao"] = nova_proxima
            salvar_agendamentos_disco()
            registrar_log(
                f"📅 Próxima execução de '{task_name}' em {nova_proxima.strftime('%d/%m/%Y %H:%M:%S')}.",
                nivel="INFO",
                origem="SCHEDULER"
            )

        time.sleep(1)


def iniciar_agendador_tarefa(task_name: str, intervalo_horas: float, proxima_execucao_existente=None, persistir: bool = True):
    if task_name not in AGENDADORES:
        return {"sucesso": False, "mensagem": f"Tarefa '{task_name}' desconhecida."}

    if AGENDADORES[task_name]["ativo"]:
        AGENDADORES[task_name]["ativo"] = False
        time.sleep(0.3)

    intervalo_num = float(intervalo_horas)
    if intervalo_num <= 0:
        return {"sucesso": False, "mensagem": "O intervalo deve ser maior que zero."}

    agora = datetime.now()
    recuperar_atrasada = False

    if proxima_execucao_existente and isinstance(proxima_execucao_existente, datetime):
        proxima_dt = proxima_execucao_existente
        if agora >= proxima_dt:
            recuperar_atrasada = True
    else:
        proxima_dt = agora + timedelta(hours=intervalo_num)

    AGENDADORES[task_name]["intervalo_horas"] = intervalo_num
    AGENDADORES[task_name]["ativo"] = True
    AGENDADORES[task_name]["proxima_execucao"] = proxima_dt

    t = threading.Thread(
        target=_loop_agendador_tarefa,
        args=(task_name, recuperar_atrasada),
        daemon=True
    )
    AGENDADORES[task_name]["thread"] = t
    t.start()

    if persistir:
        salvar_agendamentos_disco()
        registrar_log(
            f"🟢 Agendamento '{task_name}' ativado a cada {intervalo_num}h (próxima: {proxima_dt.strftime('%d/%m/%Y %H:%M:%S')}).",
            nivel="SUCCESS",
            origem="SCHEDULER"
        )

    return {
        "sucesso": True,
        "mensagem": f"Agendador de '{task_name}' ativado a cada {intervalo_num}h!",
        "proxima_execucao": proxima_dt.strftime("%d/%m/%Y %H:%M:%S"),
    }


def parar_agendador_tarefa(task_name: str):
    if task_name not in AGENDADORES:
        return {"sucesso": False, "mensagem": "Tarefa não encontrada."}

    AGENDADORES[task_name]["ativo"] = False
    AGENDADORES[task_name]["proxima_execucao"] = None
    salvar_agendamentos_disco()
    registrar_log(f"⏸️ Agendamento '{task_name}' pausado pelo administrador.", nivel="WARN", origem="SCHEDULER")
    return {"sucesso": True, "mensagem": f"Agendamento de '{task_name}' desativado."}


def obter_status_agendadores():
    status = {}
    agora = datetime.now()
    for task_name, info in AGENDADORES.items():
        tempo_restante_seg = 0
        proxima_str = None
        ultima_str = info["ultima_execucao"].strftime("%d/%m/%Y %H:%M:%S") if info["ultima_execucao"] else None

        if info["ativo"] and info["proxima_execucao"]:
            delta = (info["proxima_execucao"] - agora).total_seconds()
            tempo_restante_seg = max(0, int(delta))
            proxima_str = info["proxima_execucao"].strftime("%d/%m/%Y %H:%M:%S")

        status[task_name] = {
            "nome": info["nome"],
            "ativo": info["ativo"],
            "executando": info["executando"],
            "intervalo_horas": info["intervalo_horas"],
            "proxima_execucao": proxima_str,
            "ultima_execucao": ultima_str,
            "tempo_restante_segundos": tempo_restante_seg,
        }
    return status


def obter_logs_terminal(after_id: int = 0):
    with _LOG_LOCK:
        itens = [item for item in TERMINAL_LOGS if item["id"] > after_id]
        ultimo_id = _LOG_SEQ
    return {"logs": itens, "ultimo_id": ultimo_id}


def limpar_logs_terminal():
    with _LOG_LOCK:
        TERMINAL_LOGS.clear()
    registrar_log("🧹 Terminal limpo pelo operador.", nivel="INFO", origem="SYSTEM")


def inicializar_scheduler_com_recuperacao():
    """Inicializa uma única vez (com proteção contra múltiplos workers Gunicorn) e recupera tarefas vencidas."""
    global _SCHEDULER_INICIADO
    if _SCHEDULER_INICIADO:
        return
    _SCHEDULER_INICIADO = True

    # Evita que 2+ workers Gunicorn disparem agendadores duplicados no mesmo container
    try:
        import fcntl
        lock_fp = open(LOCK_FILE_PATH, "w")
        fcntl.flock(lock_fp.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except ImportError:
        # Windows local: prossegue normalmente
        pass
    except OSError:
        # Outro worker já detém o lock do scheduler
        return

    registrar_log("🖥️ Serviço de Agendamento & Recuperação inicializado.", nivel="INFO", origem="SCHEDULER")

    if not os.path.exists(CONFIG_FILE_PATH):
        salvar_agendamentos_disco()
        return

    try:
        with open(CONFIG_FILE_PATH, "r", encoding="utf-8") as f:
            dados = json.load(f)

        for task_name, info in dados.items():
            if task_name not in AGENDADORES:
                continue

            ultima_str = info.get("ultima_execucao")
            if ultima_str:
                try:
                    AGENDADORES[task_name]["ultima_execucao"] = datetime.fromisoformat(ultima_str)
                except Exception:
                    pass

            if info.get("ativo"):
                intervalo = float(info.get("intervalo_horas", AGENDADORES[task_name]["intervalo_horas"]))
                proxima_str = info.get("proxima_execucao")
                proxima_dt = None
                if proxima_str:
                    try:
                        proxima_dt = datetime.fromisoformat(proxima_str)
                    except Exception:
                        proxima_dt = None

                iniciar_agendador_tarefa(
                    task_name=task_name,
                    intervalo_horas=intervalo,
                    proxima_execucao_existente=proxima_dt,
                    persistir=False,
                )
    except Exception as e:
        registrar_log(f"Erro ao restaurar agendamentos do JSON: {e}", nivel="ERROR", origem="SCHEDULER")


# Dispara a restauração e recuperação automática ao carregar o módulo
inicializar_scheduler_com_recuperacao()