import uuid
from sqlalchemy import (
    Column,
    String,
    Text,
    Integer,
    DateTime,
    func,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from app.core.database import Base


class AfEmailQueue(Base):
    """
    Cola de correos electrónicos.

    Almacena correos pendientes, enviados o fallidos para:
    - Envío asincrónico
    - Reintentos automáticos
    - Priorización de mensajes
    - Auditoría de notificaciones
    """
    __tablename__ = "af_email_queue"
    __table_args__ = {"schema": "public"}

    # Identificador único del correo en cola
    email_queue_id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Email del destinatario
    recipient_email = Column(
        String(255),
        nullable=False,
        index=True,
    )

    # Nombre del destinatario
    recipient_name = Column(
        String(200),
        nullable=True,
    )

    # Asunto del correo
    subject = Column(
        String(500),
        nullable=False,
    )

    # Cuerpo HTML del correo
    body_html = Column(
        Text,
        nullable=False,
    )

    # Cuerpo en texto plano
    body_text = Column(
        Text,
        nullable=True,
    )

    # Nombre del template utilizado
    template_name = Column(
        String(100),
        nullable=True,
    )

    # Datos dinámicos del template
    template_data = Column(
        JSONB,
        nullable=True,
    )

    # Estado del correo: pending | sent | failed
    status = Column(
        String(20),
        nullable=False,
        default="pending",
        index=True,
    )

    # Prioridad del envío (menor número = mayor prioridad)
    priority = Column(
        Integer,
        nullable=False,
        default=5,
        index=True,
    )

    # Número de intentos realizados
    attempts = Column(
        Integer,
        nullable=False,
        default=0,
    )

    # Máximo de intentos permitidos
    max_attempts = Column(
        Integer,
        nullable=False,
        default=3,
    )

    # Último error registrado
    last_error = Column(
        Text,
        nullable=True,
    )

    # Fecha efectiva de envío
    sent_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Fecha de creación del registro
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Fecha programada para el envío
    scheduled_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Logs de envío asociados
    send_logs = relationship(
        "EmailSendLog",
        back_populates="email_queue",
        cascade="all, delete-orphan"
    )

    def __repr__(self):
        """
        Representación legible del correo en cola.
        """
        return (
            f"<AfEmailQueue("
            f"id={self.email_queue_id}, "
            f"recipient={self.recipient_email}, "
            f"status={self.status}, "
            f"priority={self.priority}"
            f")>"
        )
