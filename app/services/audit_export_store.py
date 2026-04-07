"""
Rutas de disco para archivos de exportación de auditoría.

Los metadatos del job viven en `af_audit_exports`; los binarios bajo
exports_base_path/files/...
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import UUID

from app.core.config import settings


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditExportJobStore:
    def __init__(self, base: Optional[Path] = None) -> None:
        self.base = Path(base or settings.exports_base_path).resolve()
        self.jobs_dir = self.base / "jobs"
        self.files_root = self.base / "files"
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self.files_root.mkdir(parents=True, exist_ok=True)

    def _job_path(self, export_id: UUID) -> Path:
        return self.jobs_dir / f"{export_id}.json"

    def save_atomic(self, job: Dict[str, Any]) -> None:
        path = self._job_path(UUID(job["export_id"]))
        data = json.dumps(job, indent=2, default=str)
        fd, tmp = tempfile.mkstemp(suffix=".json", dir=self.jobs_dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(data)
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except OSError:
                    pass

    def load(self, export_id: UUID) -> Optional[Dict[str, Any]]:
        path = self._job_path(export_id)
        if not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def delete_job_file(self, export_id: UUID) -> None:
        path = self._job_path(export_id)
        if path.is_file():
            path.unlink()

    def list_for_user(self, user_id: UUID, limit: int = 50) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        uid = str(user_id)
        for p in sorted(self.jobs_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
            try:
                j = json.loads(p.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            if j.get("request_by") == uid:
                out.append(j)
            if len(out) >= limit:
                break
        return out

    def build_file_path(self, *, primary_project_id: UUID, export_id: UUID, fmt: str) -> Path:
        now = datetime.now(timezone.utc)
        ext = fmt.lower()
        rel = Path(str(primary_project_id)) / str(now.year) / f"{now.month:02d}"
        d = self.files_root / rel
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{export_id}.{ext}"


job_store = AuditExportJobStore()
