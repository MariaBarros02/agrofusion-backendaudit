"""
Rutas para exportación de comprobantes contables (RF-INT-32).
"""

from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.dependencies.auth import get_current_user
from app.schemas.check_exports import (
    CheckExportResponse,
    CreateCheckExportRequest,
    SigningReadinessResponse,
)
from app.services.check_exports_service import CheckExportsService


router = APIRouter(prefix="/audit", tags=["Check Exports"])


@router.get(
    "/checks/signing-readiness",
    response_model=SigningReadinessResponse,
    summary="Verificar disponibilidad de firma digital para comprobantes",
)
def signing_readiness(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    service = CheckExportsService()
    return service.get_signing_readiness(db)


@router.post(
    "/checks/export",
    response_model=CheckExportResponse,
    status_code=201,
    summary="Exportar comprobante contable",
)
def export_check(
    payload: CreateCheckExportRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    service = CheckExportsService()
    return service.create_export(db, payload, current_user)


@router.get(
    "/checks/exports/{export_id}",
    response_model=CheckExportResponse,
    summary="Obtener estado de exportación de comprobante",
)
def get_export(
    export_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    service = CheckExportsService()
    return service.get_export(db, export_id, current_user)


@router.get(
    "/checks/exports/{export_id}/download",
    summary="Descargar archivo de exportación de comprobante",
)
def download_export(
    export_id: str,
    token: str,
    db: Session = Depends(get_db),
):
    service = CheckExportsService()
    file_blob, filename = service.get_file_blob(db, export_id, token)
    return Response(
        content=file_blob,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
