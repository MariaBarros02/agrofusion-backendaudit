from datetime import datetime, timezone
import time
from sqlalchemy.orm import Session
from urllib.parse import urlencode
from typing import List, Dict
from app.models.af_email_queue import AfEmailQueue
from app.models.af_email_send_log import EmailSendLog
from app.models.af_email_templates import AfEmailTemplate
from app.utils.template_render import render_template
from app.services.email_service import send_templated_email
from app.core.config import settings
import json
from urllib.parse import urlencode
from app.models.users import Users

class EmailRepository:
    """
    Repositorio encargado de la gestión de correos electrónicos del sistema.

    Responsabilidades:
    - Obtener templates de correo activos=
    """

    def get_email_template(self, db: Session, template_code: str) -> AfEmailTemplate:
        """
        Obtiene un template de correo activo por su código.

        :param db: Sesión activa de base de datos
        :param template_code: Código único del template (ej: otp_2fa)
        :return: Instancia de AfEmailTemplate
        :raises RuntimeError: Si el template no existe o está inactivo
        """
        template = (
            db.query(AfEmailTemplate)
            .filter(
                AfEmailTemplate.template_code == template_code,
                AfEmailTemplate.is_active.is_(True),
            )
            .one_or_none()
        )

        if not template:
            raise RuntimeError(f"Email template not found or inactive: {template}")

        return template


    ########################################### EJEMPLO ##############################################################
    def enqueue_otp_email(self, db: Session, user, otp_code: str, ip: str):
        """
        Encola y envía un correo de OTP (2FA).

        Flujo:
        1. Obtiene el template activo
        2. Renderiza el contenido (HTML y texto)
        3. Encola el correo
        4. Envía el correo inmediatamente
        5. Registra el log de envío
        6. Actualiza el estado de la cola

        :param db: Sesión activa de base de datos
        :param user: Usuario destinatario
        :param otp_code: Código OTP generado
        :param ip: Dirección IP del solicitante
        :return: Registro AfEmailQueue
        """
        template = self.get_email_template(db, "otp_2fa")

        # Validación de integridad del template
        if not template.body_html_template or not template.body_text_template:
            raise RuntimeError("Email template body is empty")

        # Datos dinámicos para el template
        data = {
            "user_name": user.name,
            "otp_code": otp_code,
            "expires_in": "5 minutos",
            "ip_address": ip,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec='seconds'),
        }

        # Render del contenido UNA sola vez
        body_html = render_template(template.body_html_template, data)
        body_text = render_template(template.body_text_template, data)

        # 1 Encolar correo
        email_queue = AfEmailQueue(
            recipient_email=user.email,
            recipient_name=user.name,
            subject=template.subject_template,
            body_html=body_html,
            body_text=body_text,
            template_name=template.template_name,
            template_data=data,
            status="pending",
            priority=1,
            attempts=0,
            max_attempts=5,
        )

        db.add(email_queue)
        db.flush()  # Permite obtener email_queue_id sin commit

        # 2 Enviar correo y medir tiempo de entrega
        start_time = time.monotonic()

        try:
            smtp_response = send_templated_email(
                to_email=email_queue.recipient_email,
                subject=email_queue.subject,
                body_html=email_queue.body_html,
                body_text=email_queue.body_text,
            )
            status = "sent"
        except Exception as exc:
            smtp_response = str(exc)
            status = "failed"

        delivery_time_ms = int((time.monotonic() - start_time) * 1000)

        # 3️ Registrar log de envío (append-only)
        db.add(
            EmailSendLog(
                email_queue_id=email_queue.email_queue_id,
                template_code=template.template_name,
                recipient_email=user.email,
                subject=email_queue.subject,
                status=status,
                smtp_response="success",
                sent_at=datetime.now(timezone.utc),
                delivery_time_ms=delivery_time_ms,
                ip_address=ip,
            )
        )

        # 4️ Actualizar estado del correo en la cola
        email_queue.status = status
        email_queue.attempts += 1
        
        email_queue.sent_at= datetime.now(timezone.utc)
        db.commit()

        return email_queue
