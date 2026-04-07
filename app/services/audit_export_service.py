"""
Solicitud y gestión de exportaciones de auditoría (RF-INT-08).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid
from uuid import UUID

from fastapi import Request, status

from app.core.config import settings
from app.core.errors import audit_error
from app.core.security import create_export_download_token
from app.repositories.audit_repository import AuditRepository
from app.schemas.audit import AuditExportJobResponse, CreateAuditExportRequest
from app.services.audit_export_store import job_store
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
        "mask_pii": req.mask_pii,
        "include_sensitive": req.include_sensitive,
    }


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


def create_audit_export_job(
    db,
    *,
    request: Request,
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
    ag = repo.get_project_by_code(db, code="AGROFUSION")
    if not ag:
        audit_error("INTERNAL_SERVER_ERROR", status.HTTP_500_INTERNAL_SERVER_ERROR)
    primary_project = visible[0] if visible else ag.af_project_id

    export_id = uuid.uuid4()
    filters = _filters_payload(body)
    job: Dict[str, Any] = {
        "export_id": str(export_id),
        "request_by": str(user_id),
        "primary_project_id": str(primary_project),
        "format": body.format.value,
        "filters": filters,
        "priority": body.priority.value,
        "status": "PENDING",
        "requested_at": datetime.now(timezone.utc).isoformat(),
        "export_name": body.export_name,
        "file_path": None,
        "file_size_bytes": None,
        "file_hash": None,
        "digital_signature": None,
        "kms_signature_id": None,
        "actual_records": None,
        "started_at": None,
        "completed_at": None,
        "failed_at": None,
        "error_message": None,
        "retry_count": 0,
        "next_retry_at": None,
        "download_filename": None,
        "mask_pii": body.mask_pii,
        "include_sensitive": body.include_sensitive,
        "fields": body.fields if body.fields else None,
    }

    job_store.save_atomic(job)

    session = current_user.get("session")
    ip = None
    try:
        from app.dependencies.auth import get_client_ip

        ip = get_client_ip(request)
    except Exception:
        pass

    repo.log_event_optional_term(
        db,
        action_code="EXPORT_REQUESTED",
        outcome="success",
        module_code="AUDIT_EXPORT",
        project_id=primary_project,
        actor_id=user_id,
        session_id=session.sso_session_id if session else None,
        ip=ip,
        user_agent=request.headers.get("user-agent"),
        metadata={
            "format": body.format.value,
            "filters_summary": _filters_summary(filters),
            "priority": body.priority.value,
            "export_id": str(export_id),
        },
    )

    return job_to_response(job, include_download=False)


def job_to_response(
    job: Dict[str, Any],
    *,
    include_download: bool = False,
) -> AuditExportJobResponse:
    dl = None
    exp_at = None
    dtoken = None
    if include_download and job.get("status") == "COMPLETED" and job.get("file_path"):
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


def get_job_for_user(export_id: UUID, user_id: UUID) -> Optional[Dict[str, Any]]:
    job = job_store.load(export_id)
    if not job or job.get("request_by") != str(user_id):
        return None
    return job


def list_jobs_for_user(user_id: UUID, limit: int = 50) -> List[Dict[str, Any]]:
    return job_store.list_for_user(user_id, limit=limit)
