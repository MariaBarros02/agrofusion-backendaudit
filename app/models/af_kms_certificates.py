"""
Modelo ORM para certificados X.509 asociados a claves del KMS.

Representa la tabla `af_kms_certificates`, utilizada para almacenar
certificados digitales emitidos por autoridades certificadoras.
"""

import uuid
import enum
from sqlalchemy import (
    Column,
    String,
    Text,
    DateTime,
    ForeignKey,
    Index,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from app.core.database import Base


class CertificateStatus(str, enum.Enum):
    """Estados del ciclo de vida de un certificado X.509 (RF-INT-14)."""

    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class AfKmsCertificate(Base):
    """
    Modelo ORM que representa un certificado X.509 asociado a una clave.

    Almacena certificados digitales emitidos por autoridades certificadoras
    (CA) para validar la identidad de las claves públicas.
    """

    __tablename__ = "af_kms_certificates"

    # Identificador único del certificado
    certificate_id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Clave asociada al certificado
    key_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.af_kms_keys.key_id", onupdate="NO ACTION", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Contenido del certificado en formato PEM
    certificate_pem = Column(
        Text,
        nullable=False,
    )

    # Número de serie del certificado
    serial_number = Column(
        String(128),
        nullable=False,
        index=True,
    )

    # Subject DN del certificado
    subject = Column(
        Text,
        nullable=False,
    )

    # Issuer DN de la CA que emitió el certificado
    issuer = Column(
        Text,
        nullable=False,
    )

    # Fecha de validez desde
    valid_from = Column(
        DateTime(timezone=True),
        nullable=False,
    )

    # Fecha de validez hasta
    valid_to = Column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    # Fingerprint SHA-256 sobre el certificado en formato DER (RF-INT-14).
    fingerprint = Column(
        String(64),
        nullable=False,
        unique=True,
        index=True,
    )

    # Algoritmo usado por la Root CA para firmar el certificado
    # (ej. sha256WithRSAEncryption, ecdsa-with-SHA256).
    signature_algorithm = Column(
        String(64),
        nullable=True,
    )

    # Estado del certificado: active | expired | revoked.
    status = Column(
        String(20),
        nullable=True,
        default=CertificateStatus.ACTIVE.value,
        index=True,
    )

    # Fecha de revocación (si aplica).
    revoked_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Fecha de emisión (``created_at`` lógico por RF-INT-14).
    issued_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    __table_args__ = (
        Index("ix_kms_cert_key", "key_id"),
        Index("ix_kms_cert_valid_to", "valid_to"),
        {"schema": "public"},
    )

    def __repr__(self) -> str:
        return (
            f"<AfKmsCertificate certificate_id={self.certificate_id} "
            f"key_id={self.key_id} "
            f"serial_number={self.serial_number}>"
        )

