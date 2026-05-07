"""
Modelo ORM para exportaciones de comprobantes contables.

Almacena el registro, estado y archivo comprimido de cada
exportación de lote contable solicitada por un usuario.
"""

import uuid
from sqlalchemy import Column, String, DateTime, Integer, Text, LargeBinary, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.core.database import Base


class AfAuditCheckExport(Base):
    __tablename__ = "af_audit_check_exports"
    __table_args__ = {"schema": "public"}

    export_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    check_id = Column(String(36), nullable=False, index=True)
    tenant_id = Column(UUID(as_uuid=True), nullable=True)
    requested_by = Column(
        UUID(as_uuid=True),
        ForeignKey("public.users.user_id", onupdate="NO ACTION", ondelete="NO ACTION"),
        nullable=True,
    )
    export_format = Column(String(10), nullable=False)
    export_name = Column(String(255), nullable=True)
    status = Column(String(20), nullable=False, default="PENDING")
    requested_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    file_size_bytes = Column(Integer, nullable=True)
    file_hash = Column(String(64), nullable=True)
    digital_signature_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.af_kms_signatures.signature_id", onupdate="NO ACTION", ondelete="NO ACTION"),
        nullable=True,
    )
    download_token = Column(String(36), nullable=True, unique=True, index=True)
    download_count = Column(Integer, nullable=False, default=0)
    last_downloaded_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)
    file_blob = Column(LargeBinary, nullable=True)
