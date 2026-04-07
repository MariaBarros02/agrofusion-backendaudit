"""
Persistencia de exportaciones de auditoría en `af_audit_exports`.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.af_audit_exports import AfAuditExport


def _meta_get(fj: Dict[str, Any], key: str, default: Any = None):
    return (fj or {}).get(key, default)


def audit_export_to_job_dict(row: AfAuditExport) -> Dict[str, Any]:
    """
    Convierte fila ORM al dict que esperan el worker y job_to_response.
    Metadatos internos van en filters_json con prefijo _.
    """
    fj = dict(row.filters_json or {})
    primary = _meta_get(fj, "_primary_project_id")
    return {
        "export_id": str(row.export_id),
        "request_by": str(row.requested_by),
        "primary_project_id": primary,
        "format": row.export_format,
        "filters": fj,
        "priority": row.priority or "normal",
        "status": row.status,
        "requested_at": row.requested_at.isoformat() if row.requested_at else None,
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "completed_at": row.completed_at.isoformat() if row.completed_at else None,
        "failed_at": None,
        "export_name": row.export_name,
        "file_path": row.file_path,
        "file_size_bytes": row.file_size_bytes,
        "file_hash": row.file_hash,
        "digital_signature": row.digital_signature,
        "kms_signature_id": _meta_get(fj, "_kms_signature_id"),
        "actual_records": row.record_count,
        "error_message": row.error_message,
        "retry_count": int(_meta_get(fj, "_retry_count", 0) or 0),
        "next_retry_at": _meta_get(fj, "_next_retry_at"),
        "download_filename": _meta_get(fj, "_download_filename"),
        "mask_pii": bool(_meta_get(fj, "_mask_pii", True)),
        "include_sensitive": bool(_meta_get(fj, "_include_sensitive", False)),
        "fields": row.selected_fields,
    }


def query_filters_for_worker(filters_json: Dict[str, Any]) -> Dict[str, Any]:
    """Filtros de búsqueda sin claves internas _meta."""
    return {k: v for k, v in (filters_json or {}).items() if not str(k).startswith("_")}


class AuditExportRepository:
    def create(
        self,
        db: Session,
        *,
        export_id: UUID,
        tenant_id: UUID,
        requested_by: UUID,
        export_format: str,
        filters_json: Dict[str, Any],
        selected_fields: Optional[List[str]],
        priority: str,
        export_name: Optional[str],
    ) -> AfAuditExport:
        row = AfAuditExport(
            export_id=export_id,
            tenant_id=tenant_id,
            requested_by=requested_by,
            export_format=export_format.upper()[:10],
            filters_json=filters_json,
            selected_fields=selected_fields,
            status="PENDING",
            priority=priority,
            requested_at=datetime.now(timezone.utc),
            export_name=export_name,
        )
        db.add(row)
        db.flush()
        db.refresh(row)
        return row

    def get_by_id(self, db: Session, export_id: UUID) -> Optional[AfAuditExport]:
        return db.query(AfAuditExport).filter(AfAuditExport.export_id == export_id).first()

    def get_for_user(
        self, db: Session, export_id: UUID, user_id: UUID
    ) -> Optional[AfAuditExport]:
        return (
            db.query(AfAuditExport)
            .filter(
                AfAuditExport.export_id == export_id,
                AfAuditExport.requested_by == user_id,
            )
            .first()
        )

    def list_for_user(
        self, db: Session, user_id: UUID, limit: int = 50
    ) -> List[AfAuditExport]:
        return (
            db.query(AfAuditExport)
            .filter(AfAuditExport.requested_by == user_id)
            .order_by(AfAuditExport.requested_at.desc())
            .limit(limit)
            .all()
        )

    def list_pending_candidates(self, db: Session, limit: int = 100) -> List[AfAuditExport]:
        return (
            db.query(AfAuditExport)
            .filter(AfAuditExport.status == "PENDING")
            .order_by(AfAuditExport.requested_at.asc())
            .limit(limit)
            .all()
        )

    def save_processing(
        self, db: Session, export_id: UUID, *, started_at: datetime
    ) -> None:
        row = self.get_by_id(db, export_id)
        if not row:
            return
        row.status = "PROCESSING"
        row.started_at = started_at
        fj = dict(row.filters_json or {})
        fj.pop("_next_retry_at", None)
        row.filters_json = fj
        db.commit()

    def save_completed(
        self,
        db: Session,
        export_id: UUID,
        *,
        file_path: str,
        file_size_bytes: int,
        file_hash: str,
        digital_signature: Optional[str],
        kms_signature_id: Optional[str],
        record_count: int,
        download_filename: str,
        processing_time_ms: int,
    ) -> None:
        row = self.get_by_id(db, export_id)
        if not row:
            return
        now = datetime.now(timezone.utc)
        retention_days = max(1, getattr(settings, "export_file_retention_days", 7))
        row.status = "COMPLETED"
        row.completed_at = now
        row.processing_time_ms = processing_time_ms
        row.record_count = record_count
        row.file_size_bytes = file_size_bytes
        row.file_path = file_path
        row.file_hash = file_hash
        row.digital_signature = digital_signature
        row.expires_at = now + timedelta(days=retention_days)
        fj = dict(row.filters_json or {})
        fj["_download_filename"] = download_filename
        if kms_signature_id:
            fj["_kms_signature_id"] = kms_signature_id
        else:
            fj.pop("_kms_signature_id", None)
        row.filters_json = fj
        db.commit()

    def save_failed_retry(
        self,
        db: Session,
        export_id: UUID,
        *,
        error_message: str,
        retry_count: int,
        requeue_pending: bool,
        backoff_seconds: int,
    ) -> None:
        row = self.get_by_id(db, export_id)
        if not row:
            return
        now = datetime.now(timezone.utc)
        fj = dict(row.filters_json or {})
        fj["_retry_count"] = retry_count
        if requeue_pending:
            row.status = "PENDING"
            row.started_at = None
            fj["_next_retry_at"] = (now + timedelta(seconds=backoff_seconds)).isoformat()
        else:
            row.status = "FAILED"
            row.completed_at = now
            row.processing_time_ms = None
            fj.pop("_next_retry_at", None)
        row.error_message = error_message
        row.filters_json = fj
        db.commit()

    def increment_download(self, db: Session, export_id: UUID) -> None:
        row = self.get_by_id(db, export_id)
        if not row:
            return
        row.download_count = (row.download_count or 0) + 1
        row.last_downloaded_at = datetime.now(timezone.utc)
        db.commit()

    def delete(self, db: Session, export_id: UUID) -> bool:
        row = self.get_by_id(db, export_id)
        if not row:
            return False
        db.delete(row)
        db.commit()
        return True
