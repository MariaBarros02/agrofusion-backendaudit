"""
Modelo ORM para la gestión de claves criptográficas del KMS.

Representa la tabla `af_kms_keys`, utilizada para almacenar
metadatos de claves criptográficas usadas para firma digital.
Las claves privadas nunca se almacenan aquí, solo referencias al KMS.
"""

import uuid






from datetime import datetime
from sqlalchemy import (
    Column,
    String,
    Text,
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


class KeyPurpose(str, enum.Enum):
    """Propósito de la clave criptográfica."""
    SIGNING = "signing"
    ENCRYPTION = "encryption"
    BOTH = "both"


class KeyStatus(str, enum.Enum):
    """Estado de la clave criptográfica."""
    ACTIVE = "active"
    ROTATED = "rotated"
    REVOKED = "revoked"
    EXPIRED = "expired"


class KeyAlgorithm(str, enum.Enum):
    """Algoritmos de clave soportados."""
    RSA_2048 = "RSA-2048"
    RSA_4096 = "RSA-4096"
    ECDSA_P256 = "ECDSA-P256"
    ECDSA_P384 = "ECDSA-P384"


class AfKmsKey(Base):
    """
    Modelo ORM que representa una clave criptográfica del KMS.

    Almacena metadatos de claves usadas para firma digital,
    incluyendo algoritmo, propósito, estado y referencias al KMS.
    Las claves privadas nunca se almacenan en la base de datos.
    """

    __tablename__ = "af_kms_keys"

    # Identificador único de la clave
    key_id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Proyecto/tenant asociado a la clave
    project_id = Column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
    )

    # Alias amigable de la clave (ej: 'audit-signing-key-2025')
    key_alias = Column(
        String(255),
        nullable=False,
        index=True,
    )

    # Algoritmo criptográfico usado
    algorithm = Column(
        SQLEnum(KeyAlgorithm),
        nullable=False,
    )

    # Longitud de la clave en bits
    key_length = Column(
        Integer,
        nullable=False,
    )

    # Propósito de la clave
    key_purpose = Column(
        SQLEnum(KeyPurpose),
        nullable=False,
    )

    # Clave pública en formato PEM (solo lectura)
    public_key = Column(
        Text,
        nullable=False,
    )

    # Fingerprint SHA-256 de la clave pública
    key_fingerprint = Column(
        String(64),
        nullable=False,
        unique=True,
        index=True,
    )

    # Referencia al ID de la clave en el KMS externo (si aplica)
    kms_key_reference = Column(
        String(255),
        nullable=True,
    )

    # Estado actual de la clave
    status = Column(
        SQLEnum(KeyStatus),
        nullable=False,
        default=KeyStatus.ACTIVE,
        index=True,
    )

    # Versión de la clave (incrementa en rotaciones)
    key_version = Column(
        Integer,
        nullable=False,
        default=1,
    )

    # Fecha de validez desde
    valid_from = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Fecha de validez hasta
    valid_to = Column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    # Usuario que creó la clave (opcional para desarrollo, requerido en producción)
    created_by = Column(
        UUID(as_uuid=True),
        ForeignKey("public.users.user_id", onupdate="NO ACTION", ondelete="NO ACTION"),
        nullable=True,  # Temporalmente nullable para desarrollo
    )

    # Fecha de creación
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Fecha de rotación (NULL si nunca fue rotada)
    rotated_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )

    # ID de la clave que reemplaza a esta (NULL si es la actual)
    # use_alter=True permite crear la foreign key después de crear la tabla
    supersedes_key_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.af_kms_keys.key_id", onupdate="NO ACTION", ondelete="NO ACTION", use_alter=True, name="fk_kms_key_supersedes"),
        nullable=True,
    )

    # Fin del período de gracia después de rotación
    grace_period_end = Column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Configuración de tabla
    __table_args__ = {"schema": "public"}

    def __repr__(self) -> str:
        return (
            f"<AfKmsKey key_id={self.key_id} "
            f"key_alias={self.key_alias} "
            f"algorithm={self.algorithm} "
            f"status={self.status}>"
        )

