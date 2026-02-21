"""
Modelo ORM que representa proyectos externos integrados al sistema.

Define la estructura de la tabla `af_external_projects`, utilizada
para identificar sistemas externos que reportan información o errores.
"""
import uuid
from sqlalchemy import (
    Column,
    String,
    Text,
    Boolean,
    DateTime,
    ForeignKey
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from sqlalchemy import LargeBinary

from app.core.database import Base


class AfExternalProject(Base):
    """
    Modelo ORM para proyectos externos.

    Almacena información de identificación, estado y auditoría
    de sistemas externos integrados con la plataforma.
    """

    # Nombre de la tabla en la base de datos
    __tablename__ = "af_external_projects"
    # Esquema de base de datos
    __table_args__ = {"schema": "public"}

    # Identificador único del proyecto externo
    external_project_id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )

    # Código único de la instancia del proyecto externo
    instance_code = Column(String(60))
    # Nombre del proyecto externo
    project_name = Column(String(120))
    # Nombre del cliente propietario del proyecto
    client_name = Column(String(120))
    # Nombre del cliente propietario del proyecto
    project_image = Column(LargeBinary)

    #Nombre de la extension de la imagen
    project_image_mime_type = Column(Text)

    #Nombre de la imagen
    project_image_name = Column(Text)
    # Descripción general del proyecto externo
    description = Column(Text)
    # Estado del proyecto, referenciado desde el catálogo de términos
    status_term_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.cat_terms.term_id")
    )
    # Indica si el proyecto externo está activo
    is_active = Column(Boolean, default=True)
    # Fecha de creación del registro
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )
    # Fecha de última actualización del registro
    updated_at = Column(DateTime(timezone=True))
    # Usuario que creó el registro
    created_by = Column(
        UUID(as_uuid=True),
        ForeignKey("public.users.user_id")
    )
    # Fecha de eliminación lógica del proyecto
    deleted_at = Column(DateTime(timezone=True))
    # Usuario que realizó la eliminación lógica
    deleted_by = Column(
        UUID(as_uuid=True),
        ForeignKey("public.users.user_id")
    )

    # Relaciones
    # Relación con el término de catálogo que representa el estado
    status = relationship("CatTerm")
    # Usuario que creó el proyecto externo
    creator = relationship(
        "Users",
        foreign_keys=[created_by]
    )
    # Usuario que eliminó el proyecto externo
    deleter = relationship(
        "Users",
        foreign_keys=[deleted_by]
    )
