"""
Modelo ORM de solo lectura para af_accounting_transfers.

Refleja la tabla del backend de integración en el mismo esquema
para permitir consultas de exportación desde backendaudit.
"""

import uuid
from sqlalchemy import Column, String, DateTime, Integer, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.sql import func

from app.core.database import Base


class AfAccountingTransfer(Base):
    __tablename__ = "af_accounting_transfers"
    __table_args__ = {"schema": "public", "extend_existing": True}

    transfer_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    queue_id = Column(UUID(as_uuid=True), nullable=False)
    source_project_id = Column(UUID(as_uuid=True), nullable=False)
    transaction_type = Column(String(60), nullable=False)
    payload_json = Column(JSONB, nullable=False)
    transfer_status = Column(String(20), nullable=False)
    sent_at = Column(DateTime(timezone=True), server_default=func.now())
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    accounting_entry_id = Column(UUID(as_uuid=True), nullable=True)
    response_json = Column(JSONB, nullable=True)
    error_message = Column(Text, nullable=True)
    retry_count = Column(Integer, nullable=True)
