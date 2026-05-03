"""
Worker en hilo para procesar exportaciones de auditoría sin bloquear la API.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import zipfile
from datetime import datetime, timezone
from uuid import UUID

import hashlib
import shutil
import tempfile
from pathlib import Path

from fastapi import HTTPException

from app.core.config import settings
from app.core.database import SessionLocal
from app.models.users import Users
from app.repositories.audit_repository import AuditRepository
from app.repositories.audit_export_repository import (
    AuditExportRepository,
    audit_export_to_job_dict,
    query_filters_for_worker,
)
from app.services.audit_export_signing import resolve_signing_key_for_export
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
from app.services.audit_export_service import _filters_summary
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


def _format_export_error(exc: BaseException) -> str:
    """Mensaje legible para BD/UI (p. ej. detalle HTTPException del KMS)."""
    if isinstance(exc, HTTPException):
        d = exc.detail
        if isinstance(d, dict):
            code = d.get("code")
            meta = d.get("meta")
            if code is not None:
                return f"{code}: {meta!r}"
            return repr(d)
        if d is not None:
            return str(d)
        return f"HTTPException(status_code={exc.status_code})"
    s = str(exc)
    return s if s.strip() else repr(exc)


def _build_signed_export_zip(
    *,
    data_path: Path,
    export_id: UUID,
    batch_hash: str,
    fmt: str,
    request_by: UUID,
    requester_name: str | None,
    requester_email: str | None,
    total_written: int,
    digital_signature: str,
    kms_signature_id: str,
    signing_key_id: UUID,
    exported_at: datetime,
) -> Path:
    """
    Comprime el archivo de datos y un manifest.json (batch_hash, metadatos, firma)
    en un ZIP, elimina el archivo de datos suelto y devuelve la ruta del .zip.
    """
    data_arcname = f"records{data_path.suffix}"
    manifest_basename = "manifest.json"
    manifest: dict = {
        "schema_version": 1,
        "document_type": "SIGNED_AUDIT_EXPORT",
        "export_id": str(export_id),
        "batch_hash": batch_hash,
        "hash_algorithm": "SHA-256",
        "exported_at": exported_at.isoformat(),
        "export_format": fmt,
        "record_count": total_written,
        "package": {
            "data_file": data_arcname,
            "manifest_file": manifest_basename,
            "hash_targets": f"batch_hash = SHA-256 (hex) of the raw {data_arcname} bytes (verify on extracted file).",
        },
        "requested_by": {
            "user_id": str(request_by),
            "name": requester_name,
            "email": requester_email,
        },
        "integrity": {
            "digital_signature_base64": digital_signature,
            "kms_signature_id": kms_signature_id,
            "signing_key_id": str(signing_key_id),
            "signature_format": "PKCS7",
        },
    }
    manifest_path = data_path.parent / f"{export_id}.manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    zip_path = data_path.parent / f"{export_id}.zip"
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(data_path, arcname=data_arcname)
        zf.write(manifest_path, arcname=manifest_basename)
    try:
        data_path.unlink()
    except OSError:
        pass
    try:
        manifest_path.unlink()
    except OSError:
        pass
    return zip_path


def _build_unsigned_export_zip(
    *,
    data_path: Path,
    export_id: UUID,
    batch_hash: str,
    fmt: str,
    request_by: UUID,
    requester_name: str | None,
    requester_email: str | None,
    total_written: int,
    exported_at: datetime,
    signing_key_id: UUID,
    signing_error: str,
) -> Path:
    """
    Mismo empaquetado que el firmado (registros + manifest), sin firma PKCS7.
    Se usa cuando hay clave KMS configurada pero la operación de firma falla.
    """
    data_arcname = f"records{data_path.suffix}"
    manifest_basename = "manifest.json"
    manifest: dict = {
        "schema_version": 1,
        "document_type": "UNSIGNED_AUDIT_EXPORT",
        "package_kind": "unsigned_zip",
        "export_id": str(export_id),
        "batch_hash": batch_hash,
        "hash_algorithm": "SHA-256",
        "exported_at": exported_at.isoformat(),
        "export_format": fmt,
        "record_count": total_written,
        "package": {
            "data_file": data_arcname,
            "manifest_file": manifest_basename,
            "hash_targets": f"batch_hash = SHA-256 (hex) of the raw {data_arcname} bytes (verify on extracted file).",
        },
        "requested_by": {
            "user_id": str(request_by),
            "name": requester_name,
            "email": requester_email,
        },
        "integrity": {
            "signed": False,
            "signature_format": None,
            "signing_key_id": str(signing_key_id),
            "signing_error": signing_error[:2000],
            "note": (
                "Este ZIP no incluye firma digital PKCS7 porque la firma falló; "
                "el hash del archivo de datos sigue siendo batch_hash."
            ),
        },
    }
    manifest_path = data_path.parent / f"{export_id}.manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    zip_path = data_path.parent / f"{export_id}.zip"
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(data_path, arcname=data_arcname)
        zf.write(manifest_path, arcname=manifest_basename)
    try:
        data_path.unlink()
    except OSError:
        pass
    try:
        manifest_path.unlink()
    except OSError:
        pass
    return zip_path


def _run_export_body(job: dict) -> None:
    export_id = UUID(job["export_id"])
    db = SessionLocal()
    started = datetime.now(timezone.utc)
    ar = AuditRepository()
    er = AuditExportRepository()
    request_by = UUID(job["request_by"])
    primary = UUID(job["primary_project_id"])
    f = query_filters_for_worker(job.get("filters") or {})

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
        fmt = str(job.get("format") or "").strip().upper()
        if not fmt:
            raise ValueError("format requerido")
        pdf_max = settings.export_pdf_max_rows
        if fmt == "PDF" and total > pdf_max:
            raise ValueError(
                f"PDF admite como máximo {pdf_max} filas ({total} coincidencias). "
                "Use CSV, XLSX o JSONL."
            )

        tmpdir = tempfile.mkdtemp(prefix=f"aex_{export_id}_")
        td_path = Path(tmpdir)
        try:
            ext_map = {"CSV": "csv", "JSONL": "jsonl", "XLSX": "xlsx", "PDF": "pdf"}
            ext = ext_map.get(fmt, fmt.lower())
            out_path = td_path / f"{export_id}.{ext}"

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
                writer = JsonlExportWriter(out_path, fields)
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

            data_path = out_path
            data_bytes = data_path.read_bytes()
            batch_hash = hashlib.sha256(data_bytes).hexdigest()

            key_id, kms_project_id = resolve_signing_key_for_export(db, primary)
            sig_b64 = None
            kms_sig_id = None
            final_path = data_path
            file_bytes = data_bytes
            signed_package = False
            if key_id:
                kms = KmsService()
                try:
                    sig = kms.sign_document(
                        db,
                        document_hash=batch_hash,
                        key_id=key_id,
                        hash_algorithm=HashAlgorithm.SHA256,
                        signature_format=SignatureFormat.PKCS7,
                        include_timestamp=False,
                        document_id=export_id,
                        document_type="AUDIT_EXPORT",
                        signer_user_id=request_by,
                        signing_reason="Integridad de exportación de auditoría",
                        project_id=kms_project_id,
                    )
                    sig_b64 = sig.digital_signature
                    kms_sig_id = str(sig.signature_id)
                    requester = db.query(Users).filter(Users.user_id == request_by).first()
                    package_at = datetime.now(timezone.utc)
                    final_path = _build_signed_export_zip(
                        data_path=data_path,
                        export_id=export_id,
                        batch_hash=batch_hash,
                        fmt=fmt,
                        request_by=request_by,
                        requester_name=getattr(requester, "name", None) if requester else None,
                        requester_email=getattr(requester, "email", None) if requester else None,
                        total_written=total_written,
                        digital_signature=sig_b64,
                        kms_signature_id=kms_sig_id,
                        signing_key_id=key_id,
                        exported_at=package_at,
                    )
                    file_bytes = final_path.read_bytes()
                    signed_package = True
                except Exception as sign_exc:
                    err_text = _format_export_error(sign_exc).strip() or type(sign_exc).__name__
                    logger.warning(
                        "Export %s: no se pudo firmar (%s); se empaqueta ZIP sin firma PKCS7.",
                        export_id,
                        sign_exc,
                    )
                    sig_b64 = None
                    kms_sig_id = None
                    requester = db.query(Users).filter(Users.user_id == request_by).first()
                    package_at = datetime.now(timezone.utc)
                    final_path = _build_unsigned_export_zip(
                        data_path=data_path,
                        export_id=export_id,
                        batch_hash=batch_hash,
                        fmt=fmt,
                        request_by=request_by,
                        requester_name=getattr(requester, "name", None) if requester else None,
                        requester_email=getattr(requester, "email", None) if requester else None,
                        total_written=total_written,
                        exported_at=package_at,
                        signing_key_id=key_id,
                        signing_error=err_text,
                    )
                    file_bytes = final_path.read_bytes()
                    signed_package = False
            else:
                logger.warning("Export %s: sin clave KMS activa; firma omitida", export_id)

            finished = datetime.now(timezone.utc)
            ext = str(final_path.suffix).lstrip(".").lower() or fmt.lower()
            download_filename = (
                f"AgroFusion_Auditoria_{finished.strftime('%Y%m%d_%H%M%S')}_"
                f"{total_written}reg.{ext}"
            )
            elapsed_ms = int((finished - started).total_seconds() * 1000)
            er.save_completed(
                db,
                export_id,
                file_blob=file_bytes,
                file_size_bytes=len(file_bytes),
                file_hash=batch_hash,
                digital_signature=sig_b64,
                kms_signature_id=kms_sig_id,
                record_count=total_written,
                download_filename=download_filename,
                processing_time_ms=elapsed_ms,
            )

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
                    "format": fmt,
                    "export_name": job.get("export_name"),
                    "filters_summary": _filters_summary(f),
                    "file_size": len(file_bytes),
                    "actual_records": total_written,
                    "file_hash": batch_hash,
                    "batch_hash": batch_hash,
                    "signed_package": signed_package,
                    "execution_time_seconds": round(elapsed, 3),
                },
            )

            # Notificación por correo deshabilitada temporalmente; la descarga sigue
            # disponible vía GET /audit/exports y token en la respuesta de la API.

        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    except Exception as exc:
        err_text = _format_export_error(exc)
        if isinstance(exc, HTTPException):
            logger.warning("Export %s failed: %s", export_id, err_text)
        else:
            logger.exception("Export %s failed", export_id)
        primary_pid = UUID(job["primary_project_id"])
        try:
            db.rollback()
        except Exception:
            pass
        row = er.get_by_id(db, export_id)
        if row and row.status == "COMPLETED":
            logger.warning(
                "Export %s: error tras completar el archivo (no se marca fallo): %s",
                export_id,
                err_text,
            )
            return
        if row and row.filters_json is not None:
            retries = int(row.filters_json.get("_retry_count", 0) or 0) + 1
        else:
            retries = int(job.get("retry_count") or 0) + 1
        requeue = retries < 3
        backoff = 2**retries if requeue else 0

        if not requeue:
            f_fail = query_filters_for_worker(job.get("filters") or {})
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
                        "format": job.get("format"),
                        "export_name": job.get("export_name"),
                        "filters_summary": _filters_summary(f_fail),
                        "error_message": err_text,
                        "retry_count": retries,
                    },
                )
            except Exception:
                logger.exception("Could not log EXPORT_FAILED")

        er.save_failed_retry(
            db,
            export_id,
            error_message=err_text,
            retry_count=retries,
            requeue_pending=requeue,
            backoff_seconds=backoff,
        )
    finally:
        db.close()


def _process_one_export_id(export_id: UUID) -> None:
    er = AuditExportRepository()
    with _process_lock:
        db = SessionLocal()
        try:
            row = er.get_by_id(db, export_id)
            if not row or row.status != "PENDING":
                return
            fj = dict(row.filters_json or {})
            nr = fj.get("_next_retry_at")
            if nr:
                try:
                    when = _parse_iso_dt(nr)
                    if when and datetime.now(timezone.utc) < when.replace(tzinfo=timezone.utc):
                        return
                except (TypeError, ValueError):
                    pass
            er.save_processing(
                db,
                export_id,
                started_at=datetime.now(timezone.utc),
            )
            row = er.get_by_id(db, export_id)
            cur = audit_export_to_job_dict(row) if row else None
        finally:
            db.close()

    if not cur:
        return

    # No se registra EXPORT_STARTED: cada paso añadía filas a la misma hora; el flujo
    # queda cubierto con EXPORT_REQUESTED (API) + EXPORT_COMPLETED/EXPORT_FAILED (worker).
    _run_export_body(cur)


def _loop() -> None:
    poll = max(0.5, settings.export_worker_poll_seconds)
    er = AuditExportRepository()
    while not _stop.is_set():
        try:
            db = SessionLocal()
            try:
                rows = er.list_pending_candidates(db, limit=100)
            finally:
                db.close()
            for row in rows:
                if _stop.is_set():
                    break
                _process_one_export_id(row.export_id)
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
