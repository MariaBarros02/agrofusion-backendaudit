"""
Modelo ORM para el registro de errores provenientes de sistemas externos.

Representa la tabla `af_error_log`, utilizada para almacenar
errores de auditoría con contexto, severidad y sistema de origen.
"""

import uuid
from sqlalchemy import (
    Column,
    Text,
    DateTime,
    ForeignKey,
    Index,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from app.core.database import Base


class AfErrorLog(Base):
    """
    Modelo ORM que representa un registro de error de auditoría.

    Almacena información sobre errores reportados por proyectos externos,
    incluyendo contexto, severidad, sistema origen y metadatos adicionales.
    """

    # Nombre de la tabla en la base de datos
    __tablename__ = "af_error_log"

    # Identificador único del error (UUID)
    err_id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Referencia al término de catálogo que define el contexto del error
    context_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.cat_terms.term_id", onupdate="NO ACTION", ondelete="NO ACTION"),
        nullable=False,
        index=True,
    )

    # Proyecto o sistema externo que originó el error (opcional)
    source_system_id = Column(
        UUID(as_uuid=True),
        ForeignKey(
            "public.af_external_projects.external_project_id",
            onupdate="NO ACTION",
            ondelete="NO ACTION",
        ),
        nullable=True,
        index=True,
    )

    # Mensaje descriptivo del error
    message = Column(
        Text,
        nullable=False,
    )

    # Fragmento del payload relacionado con el error (opcional)
    payload_excerpt = Column(
        Text,
        nullable=True,
    )

    # Referencia al término de catálogo que indica la severidad del error
    severity_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.cat_terms.term_id", onupdate="NO ACTION", ondelete="NO ACTION"),
        nullable=False,
        index=True,
    )

    # Fecha y hora en la que se registró el error
    at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Código interno o externo del error (opcional)
    error_code = Column(
        Text,
        nullable=True,
    )

    # Componente del sistema donde ocurrió el error (opcional)
    component = Column(
        Text,
        nullable=True,
    )

    # Índices para optimizar búsquedas por contexto, severidad y sistema origen
    __table_args__ = (
        Index("ix_err_ctx", "context_id"),
        Index("ix_err_sev", "severity_id"),
        Index("ix_err_source", "source_system_id"),
    )

    # Representación legible del registro de error para debugging y logs
    def __repr__(self) -> str:
        return (
            f"<AfErrorLog err_id={self.err_id} "
            f"severity_id={self.severity_id} "
            f"error_code={self.error_code}>"
        )
