import uuid
from sqlalchemy import (
    Column,
    String,
    Text,
    Boolean,
    JSON,
    DateTime,
    ForeignKey,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.core.database import Base


class AfEmailTemplate(Base):
    """
    Modelo ORM para templates de correo electrónico.

    Representa plantillas reutilizables para el envío de emails,
    incluyendo asunto, cuerpo HTML, cuerpo en texto plano y
    variables dinámicas permitidas.

    Este modelo está pensado para:
    - Centralizar templates de correo
    - Versionar contenido
    - Activar / desactivar templates
    - Auditoría de creación
    """
    __tablename__ = "af_email_templates"
    __table_args__ = {"schema": "public"}

    # Identificador único del template
    template_id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Código único del template (ej: otp_2fa, password_reset)
    template_code = Column(
        String(100),
        nullable=False,
        unique=True,
        index=True,
        comment="Código único del template (ej: otp_2fa)"
    )

    # Nombre descriptivo del template
    template_name = Column(
        String(200),
        nullable=False,
        comment="Nombre descriptivo del template"
    )

    # Plantilla del asunto del correo
    subject_template = Column(
        String(500),
        nullable=False,
        comment="Plantilla del asunto del correo"
    )

    # Plantilla HTML del cuerpo del correo
    body_html_template = Column(
        Text,
        nullable=False,
        comment="Plantilla HTML del correo"
    )

    # Plantilla de texto plano del correo
    body_text_template = Column(
        Text,
        nullable=False,
        comment="Plantilla de texto plano del correo"
    )

    # Variables dinámicas permitidas en el template (JSON)
    template_variables = Column(
        JSON,
        comment="Variables dinámicas disponibles para el template"
    )

    # Indica si el template está activo
    is_active = Column(
        Boolean,
        nullable=False,
        default=True,
    )

    # Versión del template (control de cambios)
    version = Column(
        String(20),
        nullable=False,
        default="1.0.0",
    )

    # Fecha de creación del template
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Fecha de última actualización del template
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    # Usuario que creó el template
    created_by = Column(
        UUID(as_uuid=True),
        ForeignKey("public.users.user_id"),
        nullable=True,
    )