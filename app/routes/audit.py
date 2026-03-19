from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session      
from app.core.database import get_db
from app.schemas.audit import ErrorExtProRequest
from app.services.audit_service import AuditService
from typing import List

router = APIRouter(prefix="/audit", tags=["Auditory"])



@router.post(
    "/register-errors-EP",
    response_model=None,
    status_code=status.HTTP_200_OK,
    summary="Registrar errores de proyectos externos",
    description=(
        "Recibe una lista de errores generados por proyectos externos y los almacena en el sistema de auditoría.\n\n"
        "El endpoint valida:\n"
        "- `context` contra el catálogo `SYSTEM_ACTION`\n"
        "- `severity` contra el catálogo `SEVERITY_GRADE`\n"
        "- `project` (opcional) contra el catálogo de proyectos externos activos\n\n"
        "Si todo es válido, persiste cada error en `af_error_log`."
    ),
    responses={
        200: {
            "description": "Errores registrados correctamente",
            "content": {
                "application/json": {
                    "examples": {
                        "ok": {"value": None}
                    }
                }
            },
        },
        404: {
            "description": "Contexto o severidad no encontrada en catálogos",
            "content": {
                "application/json": {
                    "examples": {
                        "context_not_found": {
                            "summary": "Contexto no existe",
                            "value": {"detail": {"code": "CONTEXT_NOT_FOUND", "meta": {}}},
                        },
                        "severity_not_found": {
                            "summary": "Severidad no existe",
                            "value": {"detail": {"code": "SEVERITY_NOT_FOUND", "meta": {}}},
                        },
                    }
                }
            },
        },
    },
)
def register_errors_EP(payload: List[ErrorExtProRequest], db: Session = Depends(get_db)):
    """
    ### Registrar errores desde proyectos externos

    Recibe una lista de errores generados por proyectos externos y los almacena en el
    sistema de auditoría.

    **Flujo:**
    1. Valida `context` en el catálogo `SYSTEM_ACTION`
    2. Valida `severity` en el catálogo `SEVERITY_GRADE`
    3. Si `project` viene informado, valida que exista y sea un proyecto externo activo
    4. Persiste el error en `af_error_log`
    """
    service = AuditService()
    return service.register_errors_EP(db=db, errors= payload) 