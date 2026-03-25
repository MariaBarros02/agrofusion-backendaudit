import uuid
from sqlalchemy import (
    Column,
    String,
    Text,
    DateTime,
    Integer,
    ForeignKey
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

from app.core.database import Base


class Project(Base):
    """
    Modelo ORM para proyectos del sistema.

    Usado para:
    - Agrupar auditorías
    - Asociar eventos y logs
    - Controlar estado y ciclo de vida
    """
    __tablename__ = "af_projects"
    __table_args__ = {"schema": "public"}

    # Identificador del proyecto
    af_project_id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Código único del proyecto
    code = Column(
        String(40),
        nullable=False,
        unique=True,
        index=True,
    )

    # Nombre del proyecto
    name = Column(
        String(120),
        nullable=False,
    )

    # Estado del proyecto (catálogo)
    status_term_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.cat_terms.term_id"),
        nullable=False,
    )

    # Fecha de deshabilitación
    disabled_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Usuario creador
    created_by = Column(
        UUID(as_uuid=True),
        ForeignKey("public.users.user_id"),
        nullable=False,
    )

    # Auditoría
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    updated_at = Column(
        DateTime(timezone=True),
        onupdate=func.now(),
    )

    deleted_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Descripción del proyecto
    description = Column(
        Text,
        nullable=True,
    )

    # Control de concurrencia optimista
    row_version = Column(
        Integer,
        default=1,
    )

