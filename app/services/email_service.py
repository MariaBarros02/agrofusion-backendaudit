from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib

from app.core.config import settings


def send_templated_email(
    *,
    to_email: str,
    subject: str,
    body_html: str,
    body_text: str,
) -> str:
    """
    Envía un correo electrónico utilizando SMTP con soporte
    para contenido en texto plano y HTML (multipart/alternative).

    Características:
    - Soporta clientes que solo aceptan texto plano
    - Utiliza conexión segura mediante STARTTLS
    - Autenticación SMTP mediante credenciales configuradas
    - Retorna la respuesta del servidor SMTP para logging o auditoría

    :param to_email: Dirección de correo del destinatario
    :param subject: Asunto del correo
    :param body_html: Contenido HTML del correo
    :param body_text: Contenido en texto plano del correo
    :return: Respuesta del servidor SMTP como string
    """
    msg = MIMEMultipart("alternative")
    msg["From"] = f"{settings.smtp_from_name} <{settings.smtp_user}>"
    msg["To"] = to_email
    msg["Subject"] = subject

    msg.attach(MIMEText(body_text, "plain", "utf-8"))
    msg.attach(MIMEText(body_html, "html", "utf-8"))

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as server:
        server.starttls()
        server.login(settings.smtp_user, settings.smtp_password)
        response = server.send_message(msg)

    return str(response)
