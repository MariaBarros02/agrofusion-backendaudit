"""
Solicitud y gestión de exportaciones de auditoría (RF-INT-08).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid
from uuid import UUID

from fastapi import status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.errors import audit_error
from app.core.security import create_export_download_token
from app.models.af_kms_keys import KeyPurpose
from app.repositories.audit_repository import AuditRepository
from app.repositories.audit_export_repository import (
    AuditExportRepository,
    audit_export_to_job_dict,
)
from app.repositories.kms_repository import KmsRepository
from app.schemas.audit import (
    AuditExportJobResponse,
    AuditExportSigningReadinessResponse,
    CreateAuditExportRequest,
)
from app.services.permissions_service import PermissionsService


def _iso(dt: Any) -> Optional[str]:
    if dt is None:
        return None
    if isinstance(dt, datetime):
        return dt.isoformat()
    return str(dt)


def _filters_payload(req: CreateAuditExportRequest) -> Dict[str, Any]:
    return {
        "date_from": _iso(req.date_from),
        "date_to": _iso(req.date_to),
        "user_ids": req.user_ids or [],
        "project_ids": req.project_ids or [],
        "module_codes": req.module_codes or [],
        "action_codes": req.action_codes or [],
        "outcomes": req.outcomes or [],
        "entity_types": req.entity_types or [],
        "search": req.search,
        "fields": req.fields,
    }


def _primary_project_id_for_audit_export(db: Session, visible: List[UUID]) -> UUID:
    """
    ``af_projects.af_project_id`` para metadatos del export y resolución KMS:
    primero un proyecto visible que tenga clave signing/both activa en BD;
    si ninguno, el primero visible; si la lista está vacía, el proyecto de
    cualquier clave signing activa (fallback desarrollo / usuario sin roles).
    """
    kr = KmsRepository()
    for pid in visible:
        keys = kr.get_active_keys_by_project(db, pid, KeyPurpose.SIGNING)
        if not keys:
            keys = kr.get_active_keys_by_project(db, pid, KeyPurpose.BOTH)
        if keys:
            return pid
    if visible:
        return visible[0]
    fallback = kr.get_latest_active_signing_key_any_project(db)
    if fallback:
        return fallback.project_id
    audit_error("INTERNAL_SERVER_ERROR", status.HTTP_500_INTERNAL_SERVER_ERROR)


def _filters_summary(filters: Dict[str, Any]) -> str:
    parts = []
    if filters.get("date_from") or filters.get("date_to"):
        parts.append("date_range")
    if filters.get("user_ids"):
        parts.append("users")
    if filters.get("project_ids"):
        parts.append("projects")
    if filters.get("module_codes"):
        parts.append("modules")
    if filters.get("action_codes"):
        parts.append("actions")
    return ",".join(parts) if parts else "none"


def get_audit_export_signing_readiness(
    db: Session, user_id: UUID
) -> AuditExportSigningReadinessResponse:
    """
    Comprueba si el tenant puede firmar exports (clave signing activa, material cifrado,
    certificado ACTIVE), usando la misma resolución de proyecto/clave que el worker.
    """
    from app.services.audit_export_signing import resolve_signing_key_for_export

    ar = AuditRepository()
    kr = KmsRepository()
    visible = ar.get_user_visible_project_ids(db, user_id)

    primary: UUID | None = None
    for pid in visible:
        keys = kr.get_active_keys_by_project(db, pid, KeyPurpose.SIGNING)
        if not keys:
            keys = kr.get_active_keys_by_project(db, pid, KeyPurpose.BOTH)
        if keys:
            primary = pid
            break
    if primary is None and visible:
        primary = visible[0]
    elif primary is None:
        fb0 = kr.get_latest_active_signing_key_any_project(db)
        primary = fb0.project_id if fb0 else None

    if primary is None:
        return AuditExportSigningReadinessResponse(
            ready=False, reason_code="NO_PROJECT_CONTEXT"
        )

    key_id, _ = resolve_signing_key_for_export(db, primary, log_fallback=False)
    if not key_id:
        return AuditExportSigningReadinessResponse(
            ready=False, reason_code="NO_ACTIVE_SIGNING_KEY"
        )

    key_row = kr.get_key_by_id(db, key_id)
    if not key_row or not (key_row.private_key_encrypted or "").strip():
        return AuditExportSigningReadinessResponse(
            ready=False, reason_code="NO_ENCRYPTED_PRIVATE_KEY"
        )

    cert = kr.get_active_certificate_by_key_id(db, key_id)
    if not cert:
        return AuditExportSigningReadinessResponse(
            ready=False, reason_code="NO_ACTIVE_CERTIFICATE"
        )

    return AuditExportSigningReadinessResponse(ready=True, reason_code=None)


def create_audit_export_job(
    db: Session,
    *,
    current_user: dict,
    body: CreateAuditExportRequest,
) -> AuditExportJobResponse:
    perm = PermissionsService()
    if not perm.validate_permission(
        db,
        current_user.get("role"),
        settings.audit_export_permission_code,
    ):
        audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)

    user = current_user["user"]
    user_id: UUID = user.user_id
    repo = AuditRepository()
    visible = repo.get_user_visible_project_ids(db, user_id)
    primary_project = _primary_project_id_for_audit_export(db, visible)

    export_id = uuid.uuid4()
    filters_json = _filters_payload(body)
    filters_json["_primary_project_id"] = str(primary_project)
    filters_json["_mask_pii"] = body.mask_pii
    filters_json["_include_sensitive"] = body.include_sensitive
    filters_json["_retry_count"] = 0

    # tenant_id -> af_external_projects.external_project_id (no af_projects)
    tenant_id = repo.resolve_audit_export_tenant_id(db)

    er = AuditExportRepository()
    er.create(
        db,
        export_id=export_id,
        tenant_id=tenant_id,
        requested_by=user_id,
        export_format=body.format.value,
        filters_json=filters_json,
        selected_fields=body.fields if body.fields else None,
        priority=body.priority.value,
        export_name=body.export_name,
    )
    # Persistir el job: sin commit la sesión hace rollback al cerrar y GET /exports/{id} devuelve 404.
    db.commit()

    # Un solo registro de auditoría por export: EXPORT_COMPLETED o EXPORT_FAILED (worker).

    row = er.get_by_id(db, export_id)
    job = audit_export_to_job_dict(row) if row else {}
    return job_to_response(job, include_download=False)


def job_to_response(
    job: Dict[str, Any],
    *,
    include_download: bool = False,
) -> AuditExportJobResponse:
    dl = None
    exp_at = None
    dtoken = None
    if include_download and job.get("status") == "COMPLETED" and job.get("has_file_blob"):
        try:
            ttl = settings.export_download_ttl_minutes
            token = create_export_download_token(
                export_id=UUID(job["export_id"]),
                user_id=UUID(job["request_by"]),
                project_id=UUID(job["primary_project_id"])
                if job.get("primary_project_id")
                else None,
                ttl_minutes=ttl,
            )
            from datetime import timedelta
            from urllib.parse import urlencode

            exp_at = (datetime.now(timezone.utc) + timedelta(minutes=ttl)).isoformat()
            dtoken = token
            pub = (settings.audit_api_public_url or "").strip().rstrip("/")
            if pub:
                dl = f"{pub}/audit/exports/{job['export_id']}/download?{urlencode({'token': token})}"
        except Exception:
            dl = None
            dtoken = None

    return AuditExportJobResponse(
        export_id=job["export_id"],
        status=job["status"],
        format=job["format"],
        requested_at=job.get("requested_at"),
        started_at=job.get("started_at"),
        completed_at=job.get("completed_at"),
        failed_at=job.get("failed_at"),
        export_name=job.get("export_name"),
        actual_records=job.get("actual_records"),
        file_size_bytes=job.get("file_size_bytes"),
        file_hash=job.get("file_hash"),
        digital_signature=job.get("digital_signature"),
        error_message=job.get("error_message"),
        retry_count=int(job.get("retry_count") or 0),
        download_url=dl,
        download_expires_at=exp_at,
        download_token=dtoken,
        download_filename=job.get("download_filename"),
    )


def get_job_for_user(
    db: Session, export_id: UUID, user_id: UUID
) -> Optional[Dict[str, Any]]:
    er = AuditExportRepository()
    row = er.get_for_user(db, export_id, user_id)
    if not row:
        return None
    return audit_export_to_job_dict(row)


def list_jobs_for_user(
    db: Session, user_id: UUID, limit: int = 50
) -> List[Dict[str, Any]]:
    er = AuditExportRepository()
    rows = er.list_for_user(db, user_id, limit=limit)
    return [audit_export_to_job_dict(r) for r in rows]
