"""
Modelo ORM para vocabularios de catálogo.

Los vocabularios agrupan términos reutilizables utilizados
en diferentes módulos del sistema.
"""

import uuid
from sqlalchemy import Column, String, Text, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

from app.core.database import Base


class CatVocabulary(Base):
    """
    Modelo ORM que representa un vocabulario de términos.

    Permite agrupar términos relacionados bajo un mismo dominio
    funcional o conceptual.
    """

    __tablename__ = "cat_vocabularies"
    __table_args__ = {"schema": "public"}

    # Identificador único del vocabulario
    vocabulary_id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )
    # Código único del vocabulario
    vocabulary_code = Column(
        String(50),
        nullable=False,
        unique=True
    )
    # Nombre del vocabulario
    name = Column(String(120))
    # Descripción del vocabulario
    description = Column(Text)
    # Fecha de creación del vocabulario
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    # Relaciones
    # Términos asociados al vocabulario
    terms = relationship(
        "CatTerm",
        back_populates="vocabulary",
        cascade="all, delete-orphan"
    )
