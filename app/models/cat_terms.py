"""
Modelo ORM para términos de catálogo.

Los términos representan valores parametrizables utilizados
en diferentes módulos del sistema (estados, severidades, contextos).
"""

import uuid
from sqlalchemy import (
    Column,
    String,
    Text,
    Boolean,
    DateTime,
    ForeignKey,
    UniqueConstraint
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

from app.core.database import Base


class CatTerm(Base):

    
    """
    Modelo ORM que representa un término de catálogo.

    Permite definir valores reutilizables agrupados en vocabularios,
    con soporte para jerarquías y metadatos adicionales.
    """

    __tablename__ = "cat_terms"
    __table_args__ = {"schema": "public"}

    # Identificador único del término
    term_id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )
    # Vocabulario al que pertenece el término
    vocabulary_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.cat_vocabularies.vocabulary_id"),
        nullable=False
    )
    # Código único del término dentro del vocabulario
    code = Column(String(80), nullable=False)
    # Etiqueta legible del término
    label = Column(String(120))
    # Descripción del término
    description = Column(Text)
    # Término padre para jerarquías
    parent_term_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.cat_terms.term_id")
    )
    # Información adicional en formato JSON
    extra = Column(JSONB)
    # Indica si el término está habilitado
    is_enabled = Column(Boolean, nullable=False, default=True)
    # Fecha de creación del término
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    # Relaciones
    # Relación con el vocabulario al que pertenece el término

    vocabulary = relationship(
        "CatVocabulary",
        back_populates="terms"
    )

    
