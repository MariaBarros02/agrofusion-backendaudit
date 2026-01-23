from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session      
from app.core.database import get_db
from app.schemas.audit import ErrorExtProRequest
from app.services.audit_service import AuditService
from typing import List

router = APIRouter(prefix="/audit", tags=["Auditory"])



@router.post("/register-errors-EP", response_model=None,  summary="Registrar errores de proyectos externos",
    description="Recibe una lista de errores generados por proyectos externos y los almacena en el sistema de auditoría.", responses={
    404: {
        "description": "Contexto o severidad no encontrada en catálogos"
    },
    200: {
        "description": "Errores registrados correctamente"
    }
})
def register_errors_EP( payload: List[ErrorExtProRequest],  db: Session = Depends(get_db)):
    """
        Registra errores provenientes de proyectos externos.

        Este endpoint permite que sistemas externos reporten errores
        operativos o funcionales para ser almacenados en el sistema
        de auditoría.

        - Valida contexto y severidad contra catálogos activos
        - Relaciona el error con un proyecto externo (opcional)
        - Persiste la información para análisis posterior
    """
    service = AuditService()
    return service.register_errors_EP(db=db, errors= payload) 