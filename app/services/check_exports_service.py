"""
Servicio de exportación de comprobantes contables (RF-INT-32).

Genera el archivo en formato JSON/CSV/XML, firma digitalmente
el contenido y empaqueta como ZIP en af_audit_exports.
"""

import csv
import hashlib
import io
import json
import time
import zipfile
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID
from xml.etree.ElementTree import Element, SubElement, tostring
from xml.dom import minidom

from fastapi import status
from sqlalchemy.orm import Session

from app.core.errors import audit_error
from app.models.af_kms_signatures import HashAlgorithm, SignatureFormat
from app.repositories.check_exports_repository import CheckExportsRepository
from app.schemas.check_exports import (
    CheckExportResponse,
    CreateCheckExportRequest,
    SigningReadinessResponse,
)
from app.services.kms_service import KmsService
from app.services.permissions_service import PermissionsService


EXPORT_PERMISSION = "044"


class CheckExportsService:

    def __init__(self):
        self.repo = CheckExportsRepository()
        self.kms_service = KmsService()
        self.perm_service = PermissionsService()

    # ------------------------------------------------------------------
    # Signing readiness
    # ------------------------------------------------------------------

    def get_signing_readiness(self, db: Session) -> SigningReadinessResponse:
        key = self.repo.get_active_signing_key(db)
        if not key:
            return SigningReadinessResponse(
                ready=False,
                message="NO_ACTIVE_SIGNING_KEY",
            )
        return SigningReadinessResponse(
            ready=True,
            key_id=str(key.key_id),
            key_alias=key.key_alias,
        )

    # ------------------------------------------------------------------
    # Create export
    # ------------------------------------------------------------------

    def create_export(
        self,
        db: Session,
        payload: CreateCheckExportRequest,
        current_user: dict,
    ) -> CheckExportResponse:
        if not self.perm_service.validate_permission(
            db, current_user.get("role"), EXPORT_PERMISSION
        ):
            raise audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)

        transfer = self.repo.get_transfer_by_id(db, payload.check_id)
        if not transfer:
            raise audit_error("CHECK_NOT_FOUND", status.HTTP_404_NOT_FOUND)

        t0 = time.time()

        file_bytes = self._convert(transfer.payload_json, payload.format)
        file_hash = hashlib.sha256(file_bytes).hexdigest()

        signature_value: Optional[str] = None
        signing_key = self.repo.get_active_signing_key(db)
        if signing_key:
            try:
                _user_obj = current_user.get("user")
                user_uuid = _user_obj.user_id if _user_obj else None
                sig = self.kms_service.sign_document(
                    db,
                    document_hash=file_hash,
                    key_id=signing_key.key_id,
                    hash_algorithm=HashAlgorithm.SHA256,
                    signature_format=SignatureFormat.PKCS7,
                    include_timestamp=True,
                    document_id=transfer.transfer_id,
                    document_type="ACCOUNTING_CHECK_EXPORT",
                    signer_user_id=user_uuid,
                    signing_reason="Exportación de comprobante contable",
                )
                signature_value = sig.digital_signature
            except Exception:
                pass

        project_label = self._project_label(transfer)
        date_label = datetime.now(timezone.utc).strftime("%Y%m%d")
        export_name = f"Lote contable {project_label} {date_label}"
        filename = f"lote_contable_{project_label}_{date_label}.{payload.format.lower()}"

        zip_bytes = self._build_zip(
            filename=filename,
            file_bytes=file_bytes,
            file_hash=file_hash,
            signature_value=signature_value,
            check_id=payload.check_id,
            export_format=payload.format,
            project_label=project_label,
        )

        tenant_id = transfer.source_project_id
        _user_obj = current_user.get("user")
        requested_by = _user_obj.user_id if _user_obj else None
        if not requested_by:
            raise audit_error("AUTH_INVALID_TOKEN", status.HTTP_401_UNAUTHORIZED)

        processing_ms = int((time.time() - t0) * 1000)

        record = self.repo.create_export(
            db,
            check_id=payload.check_id,
            tenant_id=tenant_id,
            requested_by=requested_by,
            export_format=payload.format,
            export_name=export_name,
            status="COMPLETED",
            file_size_bytes=len(zip_bytes),
            file_hash=file_hash,
            digital_signature=signature_value,
            file_blob=zip_bytes,
        )

        export_id = str(record.export_id)

        return CheckExportResponse(
            export_id=export_id,
            check_id=payload.check_id,
            status="COMPLETED",
            format=payload.format,
            export_name=export_name,
            requested_at=record.requested_at,
            completed_at=record.completed_at,
            expires_at=record.expires_at,
            file_size_bytes=len(zip_bytes),
            file_hash=file_hash,
            digital_signature=signature_value,
            download_token=export_id,
            download_filename=f"{export_name.replace(' ', '_')}.zip",
        )

    # ------------------------------------------------------------------
    # Get export
    # ------------------------------------------------------------------

    def get_export(self, db: Session, export_id: str, current_user: dict) -> CheckExportResponse:
        if not self.perm_service.validate_permission(
            db, current_user.get("role"), EXPORT_PERMISSION
        ):
            raise audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)

        record = self.repo.get_export_by_id(db, export_id)
        if not record:
            raise audit_error("EXPORT_NOT_FOUND", status.HTTP_404_NOT_FOUND)

        check_id = (record.filters_json or {}).get("check_id", "")

        return CheckExportResponse(
            export_id=str(record.export_id),
            check_id=check_id,
            status=record.status,
            format=record.export_format,
            export_name=record.export_name,
            requested_at=record.requested_at,
            completed_at=record.completed_at,
            expires_at=record.expires_at,
            file_size_bytes=record.file_size_bytes,
            file_hash=record.file_hash,
            digital_signature=record.digital_signature,
            download_token=str(record.export_id),
            error_message=record.error_message,
        )

    # ------------------------------------------------------------------
    # Download
    # ------------------------------------------------------------------

    def get_file_blob(self, db: Session, export_id: str, token: str):
        if token != export_id:
            raise audit_error("EXPORT_TOKEN_INVALID", status.HTTP_403_FORBIDDEN)

        record = self.repo.get_export_by_id(db, export_id)
        if not record:
            raise audit_error("EXPORT_NOT_FOUND", status.HTTP_404_NOT_FOUND)
        if not record.file_blob:
            raise audit_error("EXPORT_FILE_NOT_FOUND", status.HTTP_404_NOT_FOUND)

        self.repo.increment_download_count(db, record)
        filename = f"{(record.export_name or 'lote_contable').replace(' ', '_')}.zip"
        return record.file_blob, filename

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _parse_uuid(self, value) -> Optional[UUID]:
        if not value:
            return None
        try:
            return UUID(str(value))
        except ValueError:
            return None

    def _project_label(self, transfer) -> str:
        payload = transfer.payload_json or {}
        header = payload.get("header") or payload.get("Header") or {}
        project = (
            header.get("ProjectCode")
            or header.get("ProjectName")
            or str(transfer.source_project_id)[:8]
        )
        return str(project).replace(" ", "_")

    def _convert(self, payload_json: dict, fmt: str) -> bytes:
        if fmt == "JSON":
            return json.dumps(payload_json, indent=2, ensure_ascii=False).encode("utf-8")
        elif fmt == "CSV":
            return self._to_csv(payload_json)
        elif fmt == "XML":
            return self._to_xml(payload_json)
        raise ValueError(f"Formato desconocido: {fmt}")

    def _to_csv(self, data: dict) -> bytes:
        buf = io.StringIO()
        writer = csv.writer(buf)

        items = self._extract_item_list(data)
        if items:
            flat_rows = [dict(self._flatten(item)) for item in items if isinstance(item, dict)]
            if flat_rows:
                headers = list(dict.fromkeys(k for row in flat_rows for k in row))
                writer.writerow(headers)
                for row in flat_rows:
                    writer.writerow([row.get(h, "") for h in headers])
                return buf.getvalue().encode("utf-8")

        # fallback: key-value plano
        writer.writerow(["campo", "valor"])
        for row in self._flatten(data):
            writer.writerow(row)
        return buf.getvalue().encode("utf-8")

    def _extract_item_list(self, data: dict) -> list:
        """Busca recursivamente la lista más grande de dicts (ítems de comprobante)."""
        best: list = []

        def _search(obj):
            nonlocal best
            if isinstance(obj, list):
                dicts = [x for x in obj if isinstance(x, dict)]
                if len(dicts) > len(best):
                    best = dicts
                for x in obj:
                    _search(x)
            elif isinstance(obj, dict):
                for v in obj.values():
                    _search(v)

        _search(data)
        return best

    def _flatten(self, obj, prefix: str = "") -> list:
        rows = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                key = f"{prefix}.{k}" if prefix else k
                rows.extend(self._flatten(v, key))
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                rows.extend(self._flatten(item, f"{prefix}[{i}]"))
        else:
            rows.append((prefix, obj))
        return rows

    def _to_xml(self, data: dict) -> bytes:
        root = Element("LoteContable")
        self._dict_to_xml(root, data)
        raw = tostring(root, encoding="unicode")
        pretty = minidom.parseString(raw).toprettyxml(indent="  ")
        lines = pretty.split("\n")[1:]
        return "\n".join(lines).encode("utf-8")

    def _dict_to_xml(self, parent: Element, obj) -> None:
        if isinstance(obj, dict):
            for key, val in obj.items():
                safe_key = str(key).replace(" ", "_").replace("/", "_")
                child = SubElement(parent, safe_key)
                self._dict_to_xml(child, val)
        elif isinstance(obj, list):
            for item in obj:
                item_el = SubElement(parent, "item")
                self._dict_to_xml(item_el, item)
        else:
            parent.text = str(obj) if obj is not None else ""

    def _build_zip(
        self,
        *,
        filename: str,
        file_bytes: bytes,
        file_hash: str,
        signature_value: Optional[str],
        check_id: str = "",
        export_format: str = "",
        project_label: str = "",
    ) -> bytes:
        now_iso = datetime.now(timezone.utc).isoformat()
        ext = filename.rsplit(".", 1)[-1] if "." in filename else export_format.lower()
        data_arcname = f"records.{ext}"
        manifest: dict = {
            "schema_version": 1,
            "document_type": "SIGNED_CHECK_EXPORT" if signature_value else "UNSIGNED_CHECK_EXPORT",
            "export_id": check_id,
            "batch_hash": file_hash,
            "hash_algorithm": "SHA-256",
            "exported_at": now_iso,
            "export_format": export_format,
            "package": {
                "data_file": data_arcname,
                "manifest_file": "manifest.json",
                "hash_targets": f"batch_hash = SHA-256 (hex) of the raw {data_arcname} bytes.",
            },
            "integrity": {
                "digital_signature_base64": signature_value,
                "signature_format": "PKCS7",
            } if signature_value else {"signed": False},
        }
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(data_arcname, file_bytes)
            zf.writestr("manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False))
        return buf.getvalue()
