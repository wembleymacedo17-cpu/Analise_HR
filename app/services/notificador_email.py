import base64
import json
import os
import urllib.error
import urllib.request
from io import BytesIO
from dotenv import load_dotenv

# Carrega o .env da raiz Analise_Hr apenas se existir localmente (sem sobrescrever variáveis de produção)
DOTENV_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '.env'))
if os.path.exists(DOTENV_PATH):
    load_dotenv(dotenv_path=DOTENV_PATH, override=False)


class NotificadorEmail:
    def __init__(self):
        self.api_key_brevo = os.getenv("SENHA_KEY")
        self.email_remetente = os.getenv("EMAIL_REMETENTE")
        self.nome_remetente = "Análise de Hora Extra - FUNFARME"

    def disparar(
        self,
        destinatarios,
        assunto: str,
        corpo_texto: str = "",
        corpo_html: str = None,
        remetente: str = None,
        anexo=None,
        nome_anexo: str = None,
    ) -> tuple[bool, str | None]:
        """
        Dispara e-mails transacionais utilizando a API REST v3 do Brevo sobre HTTPS (Porta 443).
        Retorna (True, None) em caso de sucesso ou (False, mensagem_erro) em caso de falha.
        """
        remetente_final = remetente or self.email_remetente

        if not remetente_final:
            erro = "EMAIL_REMETENTE não configurado nas variáveis de ambiente."
            print(f"❌ [BREVO API ERROR] {erro}")
            return False, erro

        if not self.api_key_brevo:
            erro = "SENHA_KEY (API Key Brevo) não encontrada nas variáveis de ambiente."
            print(f"❌ [BREVO API ERROR] {erro}")
            return False, erro

        if isinstance(destinatarios, str):
            destinatarios = [destinatarios]

        to_list = [{"email": dest.strip()} for dest in destinatarios if dest and dest.strip()]
        if not to_list:
            return False, "Nenhum destinatário válido informado."

        url = "https://api.brevo.com/v3/smtp/email"
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "api-key": self.api_key_brevo,
        }

        payload = {
            "sender": {
                "name": self.nome_remetente,
                "email": remetente_final,
            },
            "to": to_list,
            "subject": assunto,
        }

        if corpo_html:
            payload["htmlContent"] = corpo_html
        if corpo_texto:
            payload["textContent"] = corpo_texto

        # Tratamento opcional de anexos (BytesIO / bytes -> base64)
        if anexo and nome_anexo:
            if isinstance(anexo, BytesIO):
                anexo.seek(0)
                conteudo_bytes = anexo.read()
                anexo.seek(0)
            elif isinstance(anexo, bytes):
                conteudo_bytes = anexo
            else:
                conteudo_bytes = str(anexo).encode("utf-8")

            payload["attachment"] = [
                {
                    "name": nome_anexo,
                    "content": base64.b64encode(conteudo_bytes).decode("utf-8"),
                }
            ]

        try:
            print(f"📧 [BREVO API LOG] Disparando e-mail para {destinatarios}...")
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")

            with urllib.request.urlopen(req, timeout=15) as response:
                if response.status in (200, 201, 202):
                    print("✅ [BREVO API LOG] E-mail entregue com sucesso!")
                    return True, None
                erro = f"Status inesperado da API Brevo: HTTP {response.status}"
                print(f"❌ [BREVO API ERROR] {erro}")
                return False, erro

        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8") if e.fp else str(e)
            erro = f"HTTP {e.code}: {error_body}"
            print(f"❌ [BREVO API ERROR] {erro}")
            return False, erro
        except Exception as e:
            erro = str(e)
            print(f"❌ [BREVO API ERROR] Falha no disparo: {erro}")
            return False, erro

    def enviar_convite_primeiro_acesso(
        self,
        destinatario: str,
        nome_gestor: str,
        cracha: str,
        codigo_hash: str,
        link_acesso: str,
        dias_validade: int,
        centros_custo: list[str] | None = None,
    ) -> tuple[bool, str | None]:
        """Envia o convite de ativação com a Hash e o link direto de primeiro acesso."""
        assunto = "Convite de Acesso - Análise de Hora Extra | FUNFARME"

        setores_txt = ", ".join(centros_custo) if centros_custo else "Conforme vínculo RH"
        setores_html = "".join(
            f"<li style='margin-bottom: 4px; color: #334155;'>{cc}</li>" for cc in (centros_custo or [])
        )
        bloco_setores_html = (
            f"""
            <div style="margin: 16px 0; padding: 12px 16px; background: #f8fafc; border-radius: 8px; border: 1px solid #e2e8f0;">
                <div style="font-size: 12px; font-weight: bold; color: #64748b; text-transform: uppercase; margin-bottom: 6px;">
                    Centros de Custo Vinculados
                </div>
                <ul style="margin: 0; padding-left: 18px; font-size: 13px;">{setores_html}</ul>
            </div>
            """
            if centros_custo
            else ""
        )

        corpo_texto = (
            f"Olá, {nome_gestor} (Crachá {cracha})!\n\n"
            f"Seu convite de acesso ao sistema Análise de Hora Extra - FUNFARME foi gerado "
            f"(válido por {dias_validade} dias).\n\n"
            f"Código de Ativação: {codigo_hash}\n"
            f"Link de Primeiro Acesso: {link_acesso}\n"
            f"Setores vinculados: {setores_txt}\n"
        )

        corpo_html = f"""
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif; background-color: #f1f5f9; padding: 28px 16px;">
            <div style="max-width: 540px; margin: 0 auto; background: #ffffff; border-radius: 14px; overflow: hidden; border: 1px solid #e2e8f0; box-shadow: 0 4px 16px rgba(15, 23, 42, 0.06);">
                <div style="background: linear-gradient(135deg, #1e3a8a, #172554); padding: 22px 28px; color: #ffffff;">
                    <h2 style="margin: 0; font-size: 18px; letter-spacing: -0.2px;">Análise de Hora Extra • FUNFARME</h2>
                    <p style="margin: 4px 0 0 0; font-size: 13px; color: #bfdbfe;">Ativação de Acesso do Gestor</p>
                </div>

                <div style="padding: 26px 28px; color: #0f172a;">
                    <p style="margin-top: 0; font-size: 14px; color: #334155;">
                        Olá, <strong>{nome_gestor}</strong> (Crachá <strong>{cracha}</strong>).
                    </p>
                    <p style="font-size: 14px; color: #334155; line-height: 1.5;">
                        Seu convite de acesso foi emitido pelo RH e é válido por <strong>{dias_validade} dias</strong>.
                        Utilize o código abaixo para cadastrar sua senha:
                    </p>

                    <div style="background: #eff6ff; border: 1.5px dashed #1e3a8a; border-radius: 10px; padding: 16px; text-align: center; margin: 20px 0;">
                        <div style="font-size: 11px; font-weight: bold; color: #1e3a8a; text-transform: uppercase; letter-spacing: 0.8px; margin-bottom: 6px;">
                            Código do Convite
                        </div>
                        <span style="font-family: monospace; font-size: 24px; font-weight: 800; letter-spacing: 3px; color: #1e3a8a;">
                            {codigo_hash}
                        </span>
                    </div>

                    {bloco_setores_html}

                    <div style="text-align: center; margin: 24px 0 18px 0;">
                        <a href="{link_acesso}" style="background-color: #1e3a8a; color: #ffffff; text-decoration: none; padding: 13px 26px; border-radius: 10px; font-weight: 700; font-size: 14px; display: inline-block;">
                            Ativar Primeiro Acesso
                        </a>
                    </div>

                    <p style="font-size: 12px; color: #64748b; margin-bottom: 0; word-break: break-all;">
                        Caso o botão não funcione, copie e cole no navegador:<br>
                        <a href="{link_acesso}" style="color: #0284c7;">{link_acesso}</a>
                    </p>
                </div>
            </div>
        </div>
        """

        return self.disparar(
            destinatarios=destinatario,
            assunto=assunto,
            corpo_texto=corpo_texto,
            corpo_html=corpo_html,
        )