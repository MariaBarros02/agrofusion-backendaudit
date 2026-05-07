from datetime import datetime, timezone, timedelta
from typing import Optional
from uuid import UUID

from sqlalchemy.orm import Session

from app.models.af_accounting_transfers import AfAccountingTransfer
from app.models.af_audit_exports import AfAuditExport
from app.models.af_kms_keys import AfKmsKey, KeyStatus, KeyPurpose


class CheckExportsRepository:

    def get_transfer_by_id(self, db: Session, check_id: str) -> Optional[AfAccountingTransfer]:
        return (
            db.query(AfAccountingTransfer)
            .filter(AfAccountingTransfer.transfer_id == check_id)
            .first()
        )

    def get_active_signing_key(self, db: Session) -> Optional[AfKmsKey]:
        now = datetime.now(timezone.utc)
        return (
            db.query(AfKmsKey)
            .filter(
                AfKmsKey.status.in_(["ACTIVE", "active"]),
                AfKmsKey.key_purpose.in_(["SIGNING", "signing", "BOTH", "both"]),
                AfKmsKey.valid_to > now,
            )
            .order_by(AfKmsKey.created_at.desc())
            .first()
        )

    def create_export(
        self,
        db: Session,
        *,
        check_id: str,
        tenant_id: UUID,
        requested_by: UUID,
        export_format: str,
        export_name: str,
        status: str,
        file_size_bytes: Optional[int],
        file_hash: Optional[str],
        digital_signature: Optional[str],
        file_blob: Optional[bytes],
        error_message: Optional[str] = None,
    ) -> AfAuditExport:
        now = datetime.now(timezone.utc)
        record = AfAuditExport(
            tenant_id=tenant_id,
            requested_by=requested_by,
            export_format=export_format,
            filters_json={"check_id": check_id},
            status=status,
            priority="normal",
            requested_at=now,
            started_at=now,
            completed_at=now if status == "COMPLETED" else None,
            expires_at=now + timedelta(days=7),
            record_count=1,
            file_size_bytes=file_size_bytes,
            file_hash=file_hash,
            digital_signature=digital_signature,
            download_count=0,
            error_message=error_message,
            export_name=export_name,
            file_blob=file_blob,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record

    def get_export_by_id(self, db: Session, export_id: str) -> Optional[AfAuditExport]:
        return (
            db.query(AfAuditExport)
            .filter(AfAuditExport.export_id == export_id)
            .first()
        )

    def increment_download_count(self, db: Session, export: AfAuditExport) -> None:
        export.download_count = (export.download_count or 0) + 1
        export.last_downloaded_at = datetime.now(timezone.utc)
        db.commit()
