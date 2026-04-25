"""
Modelo ORM para la Autoridad Certificadora Raíz (Root CA) interna del sistema.

Representa la tabla `af_kms_ca_root`, que almacena de forma segura la
información criptográfica y metadatos asociados a la CA autofirmada del
sistema AgroFusion (RF-INT-11).

Restricciones aplicadas por diseño:
- Solo puede existir un registro con status = 'active'.
- La clave privada siempre se almacena cifrada con AES-256-GCM (nunca en
  texto plano) y se expone únicamente como `private_key_encrypted`.
- El certificado es X.509 v3 autofirmado: subject == issuer.
"""

import enum
import uuid

from sqlalchemy import (
    Column,
    String,
    Text,
    DateTime,
    Index,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.core.database import Base


class CaRootStatus(str, enum.Enum):
    """Estados posibles de una Root CA."""

    ACTIVE = "active"
    ROTATED = "rotated"
    REVOKED = "revoked"


class AfKmsCaRoot(Base):
    """
    Autoridad Certificadora Raíz (Root CA) autofirmada de AgroFusion.

    Se utiliza para firmar los certificados X.509 del sistema y como
    ancla de confianza. La clave privada se guarda cifrada con
    AES-256-GCM usando la clave maestra del KMS (KMS_MASTER_KEY).
    """

    __tablename__ = "af_kms_ca_root"

    ca_id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Clave privada cifrada con AES-256-GCM usando KMS_MASTER_KEY.
    # Formato almacenado (Base64): iv(12) || ciphertext || tag(16).
    private_key_encrypted = Column(
        Text,
        nullable=False,
    )

    # Clave pública derivada del par criptográfico, en formato PEM.
    public_key = Column(
        Text,
        nullable=False,
    )

    # Certificado X.509 v3 autofirmado en formato PEM.
    certificate_pem = Column(
        Text,
        nullable=False,
    )

    # Huella digital SHA-256 sobre el certificado en formato DER (hex).
    fingerprint = Column(
        String(64),
        nullable=False,
        unique=True,
        index=True,
    )

    # Número de serie único del certificado X.509 (hex / decimal).
    serial_number = Column(
        String(128),
        nullable=False,
        unique=True,
        index=True,
    )

    # Nombre distinguido del sujeto (ej: "CN=AgroFusion Root CA").
    subject = Column(
        Text,
        nullable=False,
    )

    # Emisor del certificado; en Root CA, issuer == subject (autofirmado).
    issuer = Column(
        Text,
        nullable=False,
    )

    valid_from = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    valid_to = Column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    # La BD valida el valor mediante un CHECK constraint (active/rotated/revoked),
    # así que almacenamos el string directamente en lugar de un tipo ENUM nativo.
    status = Column(
        String(20),
        nullable=False,
        default=CaRootStatus.ACTIVE.value,
        index=True,
    )

    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    rotated_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Identificador del usuario que crea la CA. NULL se interpreta como
    # proceso automático del sistema (SYSTEM).
    created_by = Column(
        UUID(as_uuid=True),
        nullable=True,
    )

    __table_args__ = (
        Index("ix_kms_ca_root_status", "status"),
        Index("ix_kms_ca_root_valid_to", "valid_to"),
        {"schema": "public"},
    )

    def __repr__(self) -> str:
        return (
            f"<AfKmsCaRoot ca_id={self.ca_id} "
            f"subject={self.subject} status={self.status}>"
        )
