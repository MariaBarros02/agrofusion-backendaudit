"""
Modelo ORM para validaciones de firmas digitales.

Representa la tabla `af_kms_signature_validations`, utilizada para
almacenar resultados de validaciones de firmas digitales.
"""

import uuid
from sqlalchemy import (
    Column,
    String,
    Text,
    DateTime,
    ForeignKey,
    Index,
    Enum as SQLEnum,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from app.core.database import Base
import enum


class ValidationResult(str, enum.Enum):
    """Resultados posibles de validación de firma."""
    VALID = "valid"
    INVALID = "invalid"
    EXPIRED = "expired"
    REVOKED = "revoked"


class AfKmsSignatureValidation(Base):
    """
    Modelo ORM que representa una validación de firma digital.

    Almacena resultados de validaciones realizadas sobre firmas,
    incluyendo el resultado, razón y validador.
    """

    __tablename__ = "af_kms_signature_validations"

    # Identificador único de la validación
    validation_id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Firma validada
    signature_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.af_kms_signatures.signature_id", onupdate="NO ACTION", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Resultado de la validación
    validation_result = Column(
        SQLEnum(ValidationResult),
        nullable=False,
        index=True,
    )

    # Razón detallada del resultado
    validation_reason = Column(
        Text,
        nullable=True,
    )

    # Usuario o sistema que realizó la validación
    validated_by = Column(
        UUID(as_uuid=True),
        nullable=True,
    )

    # Fecha de validación
    validated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )

    # Índices + schema (un solo __table_args__: la segunda asignación no debe pisar el schema)
    __table_args__ = (
        Index("ix_kms_val_sig", "signature_id"),
        Index("ix_kms_val_result", "validation_result"),
        Index("ix_kms_val_at", "validated_at"),
        {"schema": "public"},
    )

    def __repr__(self) -> str:
        return (
            f"<AfKmsSignatureValidation validation_id={self.validation_id} "
            f"signature_id={self.signature_id} "
            f"result={self.validation_result}>"
        )

