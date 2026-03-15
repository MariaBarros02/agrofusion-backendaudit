"""
Modelo ORM para rotaciones de claves criptográficas.

Representa la tabla `af_kms_key_rotations`, utilizada para almacenar
historial de rotaciones de claves del KMS.
"""

import uuid
from sqlalchemy import (
    Column,
    String,
    Integer,
    DateTime,
    ForeignKey,
    Index,
    Enum as SQLEnum,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from app.core.database import Base
import enum


class RotationReason(str, enum.Enum):
    """Razones de rotación de claves."""
    SCHEDULED = "scheduled"
    COMPROMISED = "compromised"
    MANUAL = "manual"
    POLICY = "policy"


class AfKmsKeyRotation(Base):
    """
    Modelo ORM que representa una rotación de clave criptográfica.

    Almacena historial de rotaciones de claves, incluyendo la clave
    antigua, la nueva, razón y período de gracia.
    """

    __tablename__ = "af_kms_key_rotations"
    __table_args__ = {"schema": "public"}

    # Identificador único de la rotación
    rotation_id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Clave anterior (rotada)
    old_key_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.af_kms_keys.key_id", onupdate="NO ACTION", ondelete="NO ACTION"),
        nullable=False,
        index=True,
    )

    # Clave nueva (reemplazo)
    new_key_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.af_kms_keys.key_id", onupdate="NO ACTION", ondelete="NO ACTION"),
        nullable=False,
        index=True,
    )

    # Razón de la rotación
    rotation_reason = Column(
        SQLEnum(RotationReason),
        nullable=False,
    )

    # Período de gracia en días
    grace_period_days = Column(
        Integer,
        nullable=False,
        default=30,
    )

    # Usuario o sistema que ejecutó la rotación
    rotated_by = Column(
        UUID(as_uuid=True),
        nullable=False,
    )

    # Fecha de rotación
    rotated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )

    # Fecha de creación del registro
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Índices para optimizar búsquedas
    __table_args__ = (
        Index("ix_kms_rot_old", "old_key_id"),
        Index("ix_kms_rot_new", "new_key_id"),
        Index("ix_kms_rot_at", "rotated_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<AfKmsKeyRotation rotation_id={self.rotation_id} "
            f"old_key_id={self.old_key_id} "
            f"new_key_id={self.new_key_id}>"
        )

