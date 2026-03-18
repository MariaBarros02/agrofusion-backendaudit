from sqlalchemy import (
    Column,
    String,
    DateTime,
    ForeignKey,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB, INET
from sqlalchemy.sql import func
from app.core.database import Base
from sqlalchemy.orm import relationship
import uuid


class AuditLog(Base):
    """
    Modelo de auditoría del sistema.

    Representa un evento auditable generado por acciones del sistema
    (login, logout, errores, accesos, integraciones, etc.).

    Diseñado para:
    - Cumplimiento de auditoría
    - Trazabilidad
    - Integridad de eventos
    - No repudio
    """
    __tablename__ = "af_audit_log"
    __table_args__ = {"schema": "public"}

    # Identificador único del evento de auditoría
    audit_id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )

    # Usuario que ejecuta la acción (puede ser NULL en eventos del sistema)
    actor_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.users.user_id"),
        nullable=True
    )

    # Código de la acción auditada (LOGIN_SUCCESS, LOGIN_FAILED, etc.)
    action_code = Column(
        String(64),
        nullable=False
    )

    # Información del objetivo afectado por la acción (ej. usuario, recurso)
    target_json = Column(JSONB, nullable=True)

    # Diferencias o cambios realizados (útil para auditoría de modificaciones)
    diff_json = Column(JSONB, nullable=True)

    # Fecha de creación del evento de auditoría
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    # Dirección IP desde donde se ejecutó la acción
    actor_ip = Column(INET, nullable=True)

    # Sesión asociada al evento (si aplica)
    session_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.af_auth_sessions.sso_session_id"),
        nullable=True
    )

    # Término categorizado de la acción (catálogo de términos)
    action_term_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.cat_terms.term_id"),
        nullable=True
    )

    # Timestamp redundante para compatibilidad con otros diseños
    at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    # Proyecto externo asociado al evento (integraciones)
    external_project_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.af_external_projects.external_project_id"),
        nullable=True
    )

    # Identificador de trazabilidad distribuida
    trace_id = Column(
        UUID(as_uuid=True),
        nullable=True
    )

    # Código del módulo que generó el evento
    module_code = Column(
        String(60),
        nullable=True
    )

    # Identificador del tenant (multitenancy)
    tenant_id = Column(
        UUID(as_uuid=True),
        nullable=True
    )

    # Proyecto interno asociado al evento
    project_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.af_projects.af_project_id"),
        nullable=True
    )

    # Resultado del evento: success | failure
    outcome = Column(
        String(20),
        default="success",
        nullable=True
    )

    # Hash del payload para verificación de integridad
    payload_hash = Column(
        String(128),
        nullable=True
    )

    # Firma digital para no repudio del evento
    digital_signature = Column(
        Text,
        nullable=True
    )

    # Información del dispositivo, navegador o cliente
    device_info = Column(JSONB, nullable=True)

