"""
Exportaciones asíncronas de auditoría (`af_audit_exports`).
"""

from sqlalchemy import (
    BigInteger,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID

from app.core.database import Base


class AfAuditExport(Base):
    __tablename__ = "af_audit_exports"
    __table_args__ = {"schema": "public"}

    export_id = Column(UUID(as_uuid=True), primary_key=True)
    tenant_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.af_external_projects.external_project_id"),
        nullable=False,
        index=True,
    )
    requested_by = Column(
        UUID(as_uuid=True),
        ForeignKey("public.users.user_id"),
        nullable=False,
        index=True,
    )
    export_format = Column(String(10), nullable=False)
    filters_json = Column(JSONB, nullable=False, default=dict)
    selected_fields = Column(JSONB, nullable=True)
    status = Column(String(20), nullable=False, index=True)
    priority = Column(String(10), nullable=False, default="normal")
    requested_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    record_count = Column(Integer, nullable=True)
    file_size_bytes = Column(BigInteger, nullable=True)
    file_blob = Column(LargeBinary, nullable=True)
    file_hash = Column(String(128), nullable=True)
    digital_signature = Column(Text, nullable=True)
    download_count = Column(Integer, nullable=False, default=0)
    last_downloaded_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)
    processing_time_ms = Column(Integer, nullable=True)
    export_name = Column(String(255), nullable=True)
