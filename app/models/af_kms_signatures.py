"""
Modelo ORM para firmas digitales generadas por el KMS.

Representa la tabla `af_kms_signatures`, utilizada para almacenar
metadatos y firmas digitales de documentos y artefactos.
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


class SignatureFormat(str, enum.Enum):
    """Formatos de firma digital soportados."""
    PKCS7 = "PKCS7"
    JWS = "JWS"
    XADES = "XAdES"
    CADES = "CAdES"


class HashAlgorithm(str, enum.Enum):
    """Algoritmos de hash soportados."""
    SHA256 = "SHA-256"
    SHA384 = "SHA-384"
    SHA512 = "SHA-512"


class AfKmsSignature(Base):
    """
    Modelo ORM que representa una firma digital generada por el KMS.

    Almacena metadatos y la firma digital de documentos, reportes,
    exportaciones y otros artefactos del sistema de auditoría.
    """

    __tablename__ = "af_kms_signatures"
    __table_args__ = {"schema": "public"}

    # Identificador único de la firma
    signature_id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Clave usada para firmar
    key_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.af_kms_keys.key_id", onupdate="NO ACTION", ondelete="NO ACTION"),
        nullable=False,
        index=True,
    )

    # Hash del documento firmado
    document_hash = Column(
        String(128),
        nullable=False,
        index=True,
    )

    # Algoritmo de hash usado
    hash_algorithm = Column(
        SQLEnum(HashAlgorithm),
        nullable=False,
    )

    # Firma digital en formato base64
    digital_signature = Column(
        Text,
        nullable=False,
    )

    # Formato de la firma
    signature_format = Column(
        SQLEnum(SignatureFormat),
        nullable=False,
    )

    # Fecha de firma
    signed_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )

    # Timestamp RFC 3161 (opcional)
    rfc3161_timestamp = Column(
        Text,
        nullable=True,
    )

    # ID del documento asociado (opcional)
    document_id = Column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
    )

    # Tipo de documento firmado
    document_type = Column(
        String(100),
        nullable=True,
        index=True,
    )

    # Usuario que solicitó la firma (opcional)
    signer_user_id = Column(
        UUID(as_uuid=True),
        nullable=True,
    )

    # Razón de la firma (opcional)
    signing_reason = Column(
        Text,
        nullable=True,
    )

    # Proyecto asociado
    # NOTA: nullable=True temporalmente para evitar problemas con foreign keys
    # El project_id se obtiene automáticamente de la clave asociada
    project_id = Column(
        UUID(as_uuid=True),
        nullable=True,  # Cambiado a True para evitar constraint violations
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
        Index("ix_kms_sig_key", "key_id"),
        Index("ix_kms_sig_doc", "document_id"),
        Index("ix_kms_sig_type", "document_type"),
        Index("ix_kms_sig_project", "project_id"),
        Index("ix_kms_sig_hash", "document_hash"),
    )

    def __repr__(self) -> str:
        return (
            f"<AfKmsSignature signature_id={self.signature_id} "
            f"key_id={self.key_id} "
            f"document_type={self.document_type}>"
        )

