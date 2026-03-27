import uuid
from sqlalchemy import (
    Column,
    String,
    Text,
    Boolean,
    Integer,
    ForeignKey,
    DateTime,
    func,
)
from sqlalchemy.dialects.postgresql import UUID, INET, JSONB
from sqlalchemy.orm import relationship

from app.core.database import Base


class EmailSendLog(Base):
    """
    Log de envío de correos electrónicos.

    Registra cada intento de envío, exitoso o fallido,
    para:
    - Auditoría
    - Diagnóstico de errores SMTP
    - Métricas de entrega
    """
    __tablename__ = "af_email_send_log"
    __table_args__ = {"schema": "public"}

    # Identificador único del log
    log_id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )

    # Correo en cola asociado (puede ser NULL)
    email_queue_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.af_email_queue.email_queue_id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )

    # Código del template utilizado
    template_code = Column(String(100))

    # Email del destinatario
    recipient_email = Column(String(255), nullable=False)

    # Asunto enviado
    subject = Column(String(500), nullable=False)

    # Estado del envío: success | failed
    status = Column(String(20), nullable=False)

    # Respuesta del servidor SMTP
    smtp_response = Column(Text)

    # Fecha/hora de envío
    sent_at = Column(DateTime(timezone=True), nullable=False)

    # Tiempo de entrega en milisegundos
    delivery_time_ms = Column(Integer)

    # IP del servidor de envío
    ip_address = Column(INET)

    # Fecha de creación del log
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )

    # Relación con la cola de correos
    email_queue = relationship(
        "AfEmailQueue",
        back_populates="send_logs"
    )
