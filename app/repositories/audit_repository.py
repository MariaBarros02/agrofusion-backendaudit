from app.models.af_external_projects import AfExternalProject
from typing import List
from fastapi import status
from app.core.errors import audit_error
from sqlalchemy.orm import Session
from app.models.af_error_log import AfErrorLog
from app.models.cat_terms import CatTerm
from app.schemas.audit import ErrorExtProRequest
from app.models.af_external_projects import AfExternalProject


class AuditRepository: 
    """
    Repositorio encargado del acceso a datos para auditoría
    y proyectos externos.
    """
    def get_term_by_code(self, db, code):
        """
        Obtiene un término de catálogo activo a partir de su código.
        """
        return (
            db.query(CatTerm)
            .filter(
                CatTerm.code == code,
                CatTerm.is_enabled.is_(True)
            )
            .first()
        )

   
    def get_EP_by_code(self, db, instance_code):
        """
        Obtiene un proyecto del catálogo de proyectos externos a partir de su código.
        """
        return (
        db.query(AfExternalProject)
        .filter(
            AfExternalProject.instance_code == instance_code,
            AfExternalProject.is_active.is_(True)
        )
        .first()
    )

    def get_active_ext_pro(self, db:Session ) -> List[AfExternalProject]:
        
        """
        Obtiene un proyecto del catálogo de proyectos externos activos a partir de su código.
        """
        external_projects = (
        db.query(AfExternalProject)
        .filter(
                AfExternalProject.is_active == True,
        ).all()
        )   
        return external_projects
    

    def register_errors_EP(self, db: Session, errors: List[ErrorExtProRequest]) -> None:
        """
        Registra una lista de errores provenientes de proyectos externos
        en la tabla af_error_log.
        """

        for err in errors:
        
            
            context_term = self.get_term_by_code(db, err.context)
            if not context_term:
                raise audit_error("CONTEXT_NOT_FOUND", status.HTTP_404_NOT_FOUND)

            severity_term = self.get_term_by_code(db, err.severity)
            if not severity_term:
                raise audit_error("SEVERITY_NOT_FOUND", status.HTTP_404_NOT_FOUND)


            source_project = None
            if err.project:
                source_project = self.get_EP_by_code(
                    db, err.project
                )

            error_log = AfErrorLog(
                context_id=context_term.term_id,
                severity_id=severity_term.term_id,
                source_system_id=(
                    source_project.external_project_id
                    if source_project
                    else None
                ),
                message=err.message,
                payload_excerpt = str(err.payload_excerpt),
                error_code=err.error_code,
                component=err.component,
            )

            db.add(error_log)

        db.commit()