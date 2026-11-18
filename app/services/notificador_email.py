import base64
import json
import os
import smtplib
import ssl
import urllib.error
import urllib.request
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from io import BytesIO
from dotenv import load_dotenv

# Procura o .env tanto na raiz de Analise_Hr quanto na pasta pai (SuperMerge)
BASE_SERVICES = os.path.dirname(os.path.abspath(__file__))
CANDIDATOS_ENV = [
    os.path.abspath(os.path.join(BASE_SERVICES, '..', '..', '.env')),
    os.path.abspath(os.path.join(BASE_SERVICES, '..', '..', '..', '.env')),
]
for caminho_env in CANDIDATOS_ENV:
    if os.path.exists(caminho_env):
        load_dotenv(dotenv_path=caminho_env, override=False)


def _limpar_env(chave: str, padrao: str = "") -> str:
    val = os.getenv(chave, padrao)
    return str(val).strip().strip('"').strip("'") if val else padrao


class NotificadorEmail:
    def __init__(self):
        self.api_key_brevo = _limpar_env("SENHA_KEY")
        self.email_remetente = _limpar_env("EMAIL_REMETENTE")
        self.smtp_server = _limpar_env("SERVIDOR_BREVO", "smtp-relay.brevo.com")
        self.smtp_port = int(_limpar_env("PORTA_BREVO", "587") or 587)
        self.login_smtp = _limpar_env("LOGIN_SMTP")
        self.nome_remetente = "Análise de Hora Extra - FUNFARME"

    def _disparar_via_api_rest(
        self,
        remetente_final: str,
        to_list: list[dict],
        assunto: str,
        corpo_texto: str,
        corpo_html: str | None,
        anexo=None,
        nome_anexo: str | None = None,
    ) -> tuple[bool, str | None]:
        url = "https://api.brevo.com/v3/smtp/email"
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "api-key": self.api_key_brevo,
            "user-agent": "FUNFARME-AnaliseHoraExtra/1.0",
        }

        payload = {
            "sender": {"name": self.nome_remetente, "email": remetente_final},
            "to": to_list,
            "subject": assunto,
        }
        if corpo_html:
            payload["htmlContent"] = corpo_html
        if corpo_texto:
            payload["textContent"] = corpo_texto

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
                {"name": nome_anexo, "content": base64.b64encode(conteudo_bytes).decode("utf-8")}
            ]

        # Contexto SSL compatível com redes corporativas Windows
        ctx_ssl = ssl.create_default_context()
        try:
            import certifi
            ctx_ssl.load_verify_locations(certifi.where())
        except Exception:
            ctx_ssl.check_hostname = False
            ctx_ssl.verify_mode = ssl.CERT_NONE

        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=15, context=ctx_ssl) as response:
                resp_body = response.read().decode("utf-8", errors="ignore")
                if response.status in (200, 201, 202):
                    print(f"✅ [BREVO API] E-mail enviado com sucesso! {resp_body}")
                    return True, None
                return False, f"API HTTP {response.status}: {resp_body}"
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="ignore") if e.fp else str(e)
            return False, f"API HTTP {e.code}: {body}"
        except Exception as e:
            return False, f"API Erro: {e}"

    def _disparar_via_smtp(
        self,
        remetente_final: str,
        destinatarios: list[str],
        assunto: str,
        corpo_texto: str,
        corpo_html: str | None,
        anexo=None,
        nome_anexo: str | None = None,
    ) -> tuple[bool, str | None]:
        if not self.login_smtp or not self.api_key_brevo:
            return False, "LOGIN_SMTP ou SENHA_KEY ausentes para envio SMTP."

        msg = MIMEMultipart("alternative")
        msg["Subject"] = assunto
        msg["From"] = f"{self.nome_remetente} <{remetente_final}>"
        msg["To"] = ", ".join(destinatarios)

        if corpo_texto:
            msg.attach(MIMEText(corpo_texto, "plain", "utf-8"))
        if corpo_html:
            msg.attach(MIMEText(corpo_html, "html", "utf-8"))

        if anexo and nome_anexo:
            if isinstance(anexo, BytesIO):
                anexo.seek(0)
                conteudo_bytes = anexo.read()
                anexo.seek(0)
            elif isinstance(anexo, bytes):
                conteudo_bytes = anexo
            else:
                conteudo_bytes = str(anexo).encode("utf-8")
            part = MIMEApplication(conteudo_bytes, Name=nome_anexo)
            part["Content-Disposition"] = f'attachment; filename="{nome_anexo}"'
            msg.attach(part)

        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=15) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(self.login_smtp, self.api_key_brevo)
                server.sendmail(remetente_final, destinatarios, msg.as_string())
            print("✅ [BREVO SMTP] E-mail enviado com sucesso via SMTP!")
            return True, None
        except Exception as e:
            return False, f"SMTP Erro: {e}"

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
        remetente_final = (remetente or self.email_remetente or "").strip()

        if not remetente_final:
            erro = "EMAIL_REMETENTE não encontrado no .env."
            print(f"❌ [EMAIL ERROR] {erro}")
            return False, erro

        if not self.api_key_brevo:
            erro = "SENHA_KEY não encontrada no .env."
            print(f"❌ [EMAIL ERROR] {erro}")
            return False, erro

        if isinstance(destinatarios, str):
            destinatarios = [destinatarios]

        dests_limpos = [d.strip() for d in destinatarios if d and d.strip()]
        if not dests_limpos:
            return False, "Nenhum destinatário válido informado."

        to_list = [{"email": d} for d in dests_limpos]

        print(f"📧 [NOTIFICADOR] Enviando de '{remetente_final}' para {dests_limpos}...")

        # 1ª tentativa: API REST v3 HTTPS (Porta 443)
        ok_api, erro_api = self._disparar_via_api_rest(
            remetente_final, to_list, assunto, corpo_texto, corpo_html, anexo, nome_anexo
        )
        if ok_api:
            return True, None

        print(f"⚠️ [NOTIFICADOR] Falha na API REST ({erro_api}). Tentando fallback SMTP...")

        # 2ª tentativa: SMTP Brevo (Porta 587)
        ok_smtp, erro_smtp = self._disparar_via_smtp(
            remetente_final, dests_limpos, assunto, corpo_texto, corpo_html, anexo, nome_anexo
        )
        if ok_smtp:
            return True, None

        erro_final = f"{erro_api} | {erro_smtp}"
        print(f"❌ [NOTIFICADOR] Falha total no envio: {erro_final}")
        return False, erro_final

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