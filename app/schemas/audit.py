from pydantic import BaseModel, Field
from typing import Dict, List, Optional
from datetime import datetime
from enum import Enum

class ErrorExtProRequest(BaseModel):
    """
    Schema que representa un error enviado por un proyecto externo.

    Se utiliza para validar y documentar la información recibida
    desde sistemas externos a través del endpoint de auditoría.
    """

    context: str
    """Código del contexto donde ocurrió el error"""

    severity: str
    """Nivel de severidad del error (ej. LOW, MEDIUM, HIGH)"""

    project: Optional[str]
    """Código del proyecto externo que originó el error"""

    message: str
    """Mensaje descriptivo del error"""

    payload_excerpt: Optional[dict]
    """Fragmento del payload original que causó el error"""

    error_code: Optional[str]
    """Código interno o externo del error"""

    component: Optional[str]
    """Componente del sistema donde se produjo el error"""


class ListAuditRequest(BaseModel):
    page_index: int = 1
    page_size: int = 10

    search: Optional[str] = None
    origin: Optional[str] = None
    result: Optional[str] = None
    user_id: Optional[str] = None
    event_type: Optional[str] = None

    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None

class ListErrorsRequest(BaseModel):

    page_index: int = 1
    page_size: int = 10

    search: Optional[str] = None
    severity: Optional[str] = None
    project: Optional[str] = None
    component: Optional[str] = None
    error_code: Optional[str] = None

    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None


class ExportFormat(str, Enum):
    CSV = "CSV"
    XLSX = "XLSX"
    PDF = "PDF"
    JSONL = "JSONL"


class ExportPriority(str, Enum):
    normal = "normal"
    high = "high"


class CreateAuditExportRequest(BaseModel):
    """Solicitud de exportación asíncrona (RF-INT-08)."""

    format: ExportFormat
    priority: ExportPriority = ExportPriority.normal
    export_name: Optional[str] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    user_ids: Optional[List[str]] = None
    project_ids: Optional[List[str]] = None
    module_codes: Optional[List[str]] = None
    action_codes: Optional[List[str]] = None
    outcomes: Optional[List[str]] = None
    entity_types: Optional[List[str]] = None
    search: Optional[str] = None
    fields: Optional[List[str]] = None
    mask_pii: bool = True
    include_sensitive: bool = False


class AuditExportJobResponse(BaseModel):
    export_id: str
    status: str
    format: str
    requested_at: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    failed_at: Optional[str] = None
    export_name: Optional[str] = None
    actual_records: Optional[int] = None
    file_size_bytes: Optional[int] = None
    file_hash: Optional[str] = None
    digital_signature: Optional[str] = None
    error_message: Optional[str] = None
    retry_count: int = 0
    download_url: Optional[str] = None
    download_expires_at: Optional[str] = None
    download_token: Optional[str] = None
    download_filename: Optional[str] = None


class AuditExportDownloadQuery(BaseModel):
    token: str = Field(..., description="Token JWT de descarga temporal")