from sqlalchemy.orm import Session

from typing import List
from fastapi import Depends,status
from app.core.errors import audit_error
from app.dependencies.auth import get_current_user

from app.schemas.external_projects import ExternalProjectResponse
from app.repositories.audit_repository import AuditRepository
from app.services.permissions_service import PermissionsService

class AuditService:

    def __init__(self):
        self.audit_repo = AuditRepository()
        self.perm_service = PermissionsService()
    """
    Coordina la lógica de negocio para el registro de errores
    de proyectos externos.
    """
    def get_external_projects(self, db: Session) -> List[ExternalProjectResponse]:
        return self.audit_repo.get_active_ext_pro(db)

    """
    Valida y delega el registro de errores al repositorio de auditoría.
    """
    def register_errors_EP(self, db: Session, errors):
        self.audit_repo.register_errors_EP(db=db, errors=errors)

    """
    Obtiene los eventos de auditoría paginados con filtros.
    """
    def get_audit_logs(
        self,
        db: Session,
        
        page_index: int,
        page_size: int,
        search: str = None,
        origin: str = None,
        result: str = None,
        user_id: str = None,
        event_type: str = None,
        start_date=None,
        end_date=None,
        current_user=Depends(get_current_user),
    ):
        if not self.perm_service.validate_permission(
            db, 
            current_user.get('role'), 
            "030"  # Código del permiso para listar auditoria
        ):
            audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)


        logs, total = self.audit_repo.list_audit_logs(
            db=db,
            page_index=page_index,
            page_size=page_size,
            search=search,
            origin=origin,
            result=result,
            user_id=user_id,
            event_type=event_type,
            start_date=start_date,
            end_date=end_date
        )

        total_pages = (total + page_size - 1) // page_size

        items = []

        for log, user_name, label, description in logs:
            items.append({
                "event_id": log.audit_id,
                "origin": log.module_code,
                "result": log.outcome,
                "action": label,
                "description": description,
                "user": user_name if user_name else log.actor_id,
                "message": log.target_json,
                "date": log.created_at
            })

        return {
            "items": items,
            "total": total,
            "page": page_index,
            "size": page_size,
            "total_pages": total_pages
        }

    def list_users(self, db: Session):
        return self.audit_repo.list_users(db)

    """
    Obtiene los errores paginados con filtros.
    """
    def get_errors_EP(
        self,
        db: Session,
        
        page_index: int,
        page_size: int,
        search: str = None,
        severity: str = None,
        project: str = None,
        component: str = None,
        error_code: str = None,
        start_date=None,
        end_date=None
    ):

        errors, total = self.audit_repo.list_errors_EP(
            db=db,
            page_index=page_index,
            page_size=page_size,
            search=search,
            severity=severity,
            project=project,
            component=component,
            error_code=error_code,
            start_date=start_date,
            end_date=end_date
        )

        total_pages = (total + page_size - 1) // page_size

        items = []

        for err, severity_name, project_name in errors:
            items.append({
                "error_id": str(err.err_id),
                "component": err.component,
                "severity": severity_name,
                "project": project_name if project_name else "N/A",
                "message": err.message,
                "error_code": err.error_code,
                "date": err.at
            })

        return {
            "items": items,
            "total": total,
            "page": page_index,
            "size": page_size,
            "total_pages": total_pages
        }

    def get_error_components(self, db: Session):
        return self.audit_repo.list_error_components(db)

    def get_error_codes(self, db: Session):
        return self.audit_repo.list_error_codes(db)