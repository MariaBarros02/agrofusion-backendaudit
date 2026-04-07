"""
Worker en hilo para procesar exportaciones de auditoría sin bloquear la API.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from uuid import UUID

import hashlib
from pathlib import Path

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.security import create_export_download_token
from app.models.users import Users
from app.repositories.audit_repository import AuditRepository
from app.repositories.kms_repository import KmsRepository
from app.repositories.email_repository import EmailRepository
from app.models.af_kms_keys import KeyPurpose
from app.models.af_kms_signatures import HashAlgorithm, SignatureFormat
from app.services.audit_export_formats import (
    EXPORT_FIELDS_PDF,
    EXPORT_FIELDS_TABULAR,
    CsvExportWriter,
    JsonlExportWriter,
    PdfExportWriter,
    XlsxExportWriter,
    build_export_row,
)
from app.services.audit_export_store import job_store
from app.services.kms_service import KmsService

logger = logging.getLogger(__name__)

_stop = threading.Event()
_worker_thread: threading.Thread | None = None
_process_lock = threading.Lock()


def _parse_iso_dt(value: str | None):
    if not value:
        return None
    s = value.replace("Z", "+00:00")
    return datetime.fromisoformat(s)


def _resolve_signing_key_id(db) -> UUID | None:
    ar = AuditRepository()
    kr = KmsRepository()
    if settings.export_signing_key_id:
        try:
            return UUID(settings.export_signing_key_id)
        except ValueError:
            return None
    project = ar.get_project_by_code(db, code="AGROFUSION")
    if not project:
        return None
    keys = kr.get_active_keys_by_project(db, project.af_project_id, KeyPurpose.SIGNING)
    if not keys:
        keys = kr.get_active_keys_by_project(db, project.af_project_id, KeyPurpose.BOTH)
    if not keys:
        return None
    return keys[0].key_id


def _run_export_body(job: dict) -> None:
    export_id = UUID(job["export_id"])
    db = SessionLocal()
    started = datetime.now(timezone.utc)
    ar = AuditRepository()
    request_by = UUID(job["request_by"])
    primary = UUID(job["primary_project_id"])
    f = job["filters"]

    try:
        visible = ar.get_user_visible_project_ids(db, request_by)
        user_ids = [UUID(x) for x in (f.get("user_ids") or [])]
        project_ids_filter = [UUID(x) for x in (f.get("project_ids") or [])]

        base = ar.build_audit_export_query(
            db,
            visible_project_ids=visible,
            search=f.get("search"),
            date_from=_parse_iso_dt(f.get("date_from")),
            date_to=_parse_iso_dt(f.get("date_to")),
            user_ids=user_ids or None,
            project_ids_filter=project_ids_filter or None,
            module_codes=f.get("module_codes") or None,
            action_codes=f.get("action_codes") or None,
            outcomes=f.get("outcomes") or None,
            entity_types=f.get("entity_types") or None,
        )
        total = ar.count_audit_export(db, base)
        fmt = job["format"]
        pdf_max = settings.export_pdf_max_rows
        if fmt == "PDF" and total > pdf_max:
            raise ValueError(
                f"PDF admite como máximo {pdf_max} filas ({total} coincidencias). "
                "Use CSV, XLSX o JSONL."
            )

        out_path = job_store.build_file_path(
            primary_project_id=primary,
            export_id=export_id,
            fmt=fmt,
        )
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if out_path.exists():
            out_path.unlink()

        raw_fields = job.get("fields")
        if raw_fields:
            fields = list(raw_fields)
        else:
            fields = list(EXPORT_FIELDS_PDF if fmt == "PDF" else EXPORT_FIELDS_TABULAR)
        chunk = max(100, settings.export_chunk_size)
        mask_pii = bool(job.get("mask_pii", True))
        include_sensitive = bool(job.get("include_sensitive", False))

        if fmt == "CSV":
            writer: object = CsvExportWriter(out_path, fields)
        elif fmt == "JSONL":
            writer = JsonlExportWriter(out_path)
        elif fmt == "XLSX":
            writer = XlsxExportWriter(out_path, fields)
        elif fmt == "PDF":
            title = job.get("export_name") or "Informe de auditoría"
            writer = PdfExportWriter(
                out_path,
                fields,
                title,
                subtitle=(
                    f"Generado {datetime.now(timezone.utc).strftime('%d/%m/%Y %H:%M UTC')} · "
                    f"AgroFusion · {total} registro(s) coincidente(s) con el filtro"
                ),
            )
        else:
            raise ValueError(f"Formato no soportado: {fmt}")

        total_written = 0
        offset = 0
        while offset < total:
            batch = ar.fetch_audit_export_batch(db, base, offset, chunk)
            if not batch:
                break
            rows = []
            for row in batch:
                log = row[0]
                actor_email = row[1]
                actor_name = row[2] if len(row) > 2 else None
                action_label = row[3] if len(row) > 3 else None
                full = build_export_row(
                    log,
                    actor_email=actor_email,
                    actor_name=actor_name,
                    action_label=action_label,
                    mask_pii=mask_pii,
                    include_sensitive=include_sensitive,
                )
                rows.append({k: full[k] for k in fields if k in full})
            writer.write_rows(rows)
            total_written += len(rows)
            offset += chunk

        writer.close()

        file_bytes = out_path.read_bytes()
        file_hash = hashlib.sha256(file_bytes).hexdigest()

        key_id = _resolve_signing_key_id(db)
        sig_b64 = None
        kms_sig_id = None
        if key_id:
            kms = KmsService()
            sig = kms.sign_document(
                db,
                document_hash=file_hash,
                key_id=key_id,
                hash_algorithm=HashAlgorithm.SHA256,
                signature_format=SignatureFormat.PKCS7,
                include_timestamp=False,
                document_id=export_id,
                document_type="AUDIT_EXPORT",
                signer_user_id=request_by,
                signing_reason="Integridad de exportación de auditoría",
                project_id=primary,
            )
            sig_b64 = sig.digital_signature
            kms_sig_id = str(sig.signature_id)
        else:
            logger.warning("Export %s: sin clave KMS activa; firma omitida", export_id)

        finished = datetime.now(timezone.utc)
        ext = str(out_path.suffix).lstrip(".").lower() or fmt.lower()
        download_filename = (
            f"AgroFusion_Auditoria_{finished.strftime('%Y%m%d_%H%M%S')}_"
            f"{total_written}reg.{ext}"
        )
        job.update(
            {
                "status": "COMPLETED",
                "completed_at": finished.isoformat(),
                "file_path": str(out_path),
                "file_size_bytes": len(file_bytes),
                "file_hash": file_hash,
                "digital_signature": sig_b64,
                "kms_signature_id": kms_sig_id,
                "actual_records": total_written,
                "error_message": None,
                "failed_at": None,
                "download_filename": download_filename,
            }
        )
        job_store.save_atomic(job)

        elapsed = (finished - started).total_seconds()
        ar.log_event_optional_term(
            db,
            action_code="EXPORT_COMPLETED",
            outcome="success",
            module_code="AUDIT_EXPORT",
            project_id=primary,
            actor_id=request_by,
            metadata={
                "export_request_id": str(export_id),
                "file_size": len(file_bytes),
                "actual_records": total_written,
                "file_hash": file_hash,
                "execution_time_seconds": round(elapsed, 3),
            },
        )

        user = db.query(Users).filter(Users.user_id == request_by).first()
        if user and user.email:
            token = create_export_download_token(
                export_id=export_id,
                user_id=request_by,
                project_id=primary,
                ttl_minutes=settings.export_download_ttl_minutes,
            )
            pub = (settings.audit_api_public_url or "").strip().rstrip("/")
            from urllib.parse import urlencode

            link = (
                f"{pub}/audit/exports/{export_id}/download?{urlencode({'token': token})}"
                if pub
                else ""
            )
            expires = (
                datetime.now(timezone.utc)
                + timedelta(minutes=settings.export_download_ttl_minutes)
            ).isoformat()
            EmailRepository().send_export_ready_notification(
                db,
                user=user,
                export_name=job.get("export_name") or "Auditoría",
                export_format=fmt,
                record_count=total_written,
                download_url=link or None,
                download_token=token,
                file_hash=file_hash,
                expires_at_iso=expires,
            )

    except Exception as exc:
        logger.exception("Export %s failed", export_id)
        primary_pid = UUID(job["primary_project_id"])
        fresh = job_store.load(export_id) or job
        retries = int(fresh.get("retry_count") or 0) + 1
        fresh["retry_count"] = retries
        fresh["failed_at"] = datetime.now(timezone.utc).isoformat()
        fresh["error_message"] = str(exc)

        try:
            ar.log_event_optional_term(
                db,
                action_code="EXPORT_FAILED",
                outcome="error",
                module_code="AUDIT_EXPORT",
                project_id=primary_pid,
                actor_id=request_by,
                metadata={
                    "export_request_id": str(export_id),
                    "error_message": str(exc),
                    "retry_count": retries,
                },
            )
        except Exception:
            logger.exception("Could not log EXPORT_FAILED")

        if retries < 3:
            backoff = 2**retries
            fresh["status"] = "PENDING"
            fresh["next_retry_at"] = (
                datetime.now(timezone.utc) + timedelta(seconds=backoff)
            ).isoformat()
            fresh["started_at"] = None
        else:
            fresh["status"] = "FAILED"
        job_store.save_atomic(fresh)
    finally:
        db.close()


def _process_one_job(job_path) -> None:
    path = Path(job_path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return

    if data.get("status") != "PENDING":
        return

    nr = data.get("next_retry_at")
    if nr:
        try:
            when = _parse_iso_dt(nr)
            if when and datetime.now(timezone.utc) < when.replace(tzinfo=timezone.utc):
                return
        except (TypeError, ValueError):
            pass

    export_id = UUID(data["export_id"])
    cur: dict | None = None
    with _process_lock:
        cur = job_store.load(export_id)
        if not cur or cur.get("status") != "PENDING":
            return
        cur["status"] = "PROCESSING"
        cur["started_at"] = datetime.now(timezone.utc).isoformat()
        cur["next_retry_at"] = None
        job_store.save_atomic(cur)

    if not cur:
        return

    db = SessionLocal()
    try:
        AuditRepository().log_event_optional_term(
            db,
            action_code="EXPORT_STARTED",
            outcome="success",
            module_code="AUDIT_EXPORT",
            project_id=UUID(cur["primary_project_id"]),
            actor_id=UUID(cur["request_by"]),
            metadata={"export_request_id": str(export_id)},
        )
    except Exception:
        pass
    finally:
        db.close()

    _run_export_body(cur)


def _loop() -> None:
    poll = max(0.5, settings.export_worker_poll_seconds)
    while not _stop.is_set():
        try:
            paths = sorted(job_store.jobs_dir.glob("*.json"))
            for p in paths:
                if _stop.is_set():
                    break
                _process_one_job(p)
        except Exception:
            logger.exception("Export worker loop error")
        _stop.wait(poll)


def start_audit_export_worker() -> None:
    global _worker_thread
    if _worker_thread and _worker_thread.is_alive():
        return
    _stop.clear()
    _worker_thread = threading.Thread(target=_loop, name="audit-export-worker", daemon=True)
    _worker_thread.start()
    logger.info("Audit export worker started")


def stop_audit_export_worker() -> None:
    _stop.set()
    if _worker_thread:
        _worker_thread.join(timeout=5.0)
