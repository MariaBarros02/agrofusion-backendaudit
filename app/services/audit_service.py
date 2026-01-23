from sqlalchemy.orm import Session
from typing import List
from app.schemas.external_projects import ExternalProjectResponse
from app.repositories.audit_repository import AuditRepository

class AuditService: 

    def __init__(self): 
        self.audit_repo = AuditRepository()

    """
    Coordina la lógica de negocio para el registro de errores
    de proyectos externos.
    """
    def get_external_projects(self, db:Session) -> List[ExternalProjectResponse]:
        external_projects = self.audit_repo.get_active_ext_pro(db)
        return external_projects;


    """
    Valida y delega el registro de errores al repositorio de auditoría.
    """
    def register_errors_EP(self, db:Session,  errors ):
        self.audit_repo.register_errors_EP(db=db, errors=errors)
        
