from datetime import datetime
from typing import Literal, Optional
from pydantic import BaseModel, Field


class CreateCheckExportRequest(BaseModel):
    check_id: str = Field(..., description="UUID del comprobante contable a exportar")
    format: Literal["JSON", "CSV", "XML"] = Field(..., description="Formato de exportación")


class CheckExportResponse(BaseModel):
    export_id: str
    check_id: str
    status: str
    format: str
    export_name: Optional[str] = None
    requested_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    file_size_bytes: Optional[int] = None
    file_hash: Optional[str] = None
    digital_signature: Optional[str] = None
    error_message: Optional[str] = None
    download_token: Optional[str] = None
    download_filename: Optional[str] = None

    class Config:
        from_attributes = True


class SigningReadinessResponse(BaseModel):
    ready: bool
    message: Optional[str] = None
    key_id: Optional[str] = None
    key_alias: Optional[str] = None
