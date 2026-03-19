from app.models.af_external_projects import AfExternalProject
from typing import List
from fastapi import status
from app.core.errors import audit_error
from sqlalchemy.orm import Session
from app.models.af_error_log import AfErrorLog
from app.models.cat_terms import CatTerm
from app.schemas.audit import ErrorExtProRequest
from app.models.af_audit_log import AfAuditLog
from app.models.users import Users
import uuid
from sqlalchemy import func
from sqlalchemy import cast, String




class AuditRepository: 
    """
    Repositorio encargado del acceso a datos para auditoría
    y proyectos externos.
    """
    def get_term_by_code(self, db, code, vocabulary):
        """
        Obtiene un término de catálogo activo a partir de su código.
        """
        return (
            db.query(CatTerm)
            .join(CatTerm.vocabulary)
            .filter(
                CatTerm.code == code,
                CatTerm.vocabulary.has(vocabulary_code=vocabulary)
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
        
            
            context_term = self.get_term_by_code(db, err.context, "SYSTEM_ACTION")
            if not context_term:
                raise audit_error("CONTEXT_NOT_FOUND", status.HTTP_404_NOT_FOUND)

            severity_term = self.get_term_by_code(db, err.severity, "SEVERITY_GRADE")
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

    def list_audit_logs(
            self,
            db: Session,
            page_index: int,
            page_size: int,
            search: str = None,
            origin: str = None,
            result: str = None,
            user_id: str = None,
            event_type: str = None,
            start_date = None,
            end_date = None
        ):
            """
            Obtiene eventos de auditoría con filtros y paginación.
            """

            query = (
             db.query(AfAuditLog, Users.name)
                .outerjoin(Users, Users.user_id == AfAuditLog.actor_id)
            )

            if search:
                query = query.filter(
                    cast(AfAuditLog.audit_id, String).ilike(f"%{search}%")
                )

            if origin:
                query = query.filter(AfAuditLog.module_code == origin)

            if result:
                query = query.filter(func.lower(AfAuditLog.outcome) == result.lower())

            if user_id:
                query = query.filter(AfAuditLog.actor_id == uuid.UUID(user_id))

            if event_type:
                query = query.filter(AfAuditLog.action_code == event_type)

            if start_date:
                query = query.filter(AfAuditLog.created_at >= start_date)

            if end_date:
                query = query.filter(AfAuditLog.created_at <= end_date)


            total = query.count()

            logs = (
                query
                .order_by(AfAuditLog.created_at.desc())
                .offset((page_index - 1) * page_size)
                .limit(page_size)
                .all()
            )

            return logs, total
    

    def list_users(self, db: Session):
        """
        Obtiene todos los usuarios activos del sistema
        """

        users = (
            db.query(Users.user_id, Users.name)
            .filter(Users.deleted_at.is_(None))
            .order_by(Users.name.asc())
            .all()
        )

        return users
    
    def list_origins(self, db: Session):
        """
        Obtiene los orígenes disponibles en la auditoría
        """

        origins = (
        db.query(AfAuditLog.module_code)
        .distinct()
        .order_by(AfAuditLog.module_code.asc())
        .all()
        )

        return origins
    
    def list_events(self, db: Session):
        """
        Obtiene los tipos de eventos registrados en la auditoría
        """

        events = (
        db.query(AfAuditLog.action_code)
        .distinct()
        .order_by(AfAuditLog.action_code.asc())
        .all()
    )

        return events
    
    def list_results(self, db: Session):
        """
        Obtiene los resultados disponibles en la auditoría
        """

        results = (
            db.query(AfAuditLog.outcome)
            .distinct()
            .order_by(AfAuditLog.outcome.asc())
            .all()
        )

        return results

    def list_errors_EP(
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

        query = (
            db.query(
                AfErrorLog,
                CatTerm.code.label("severity_name"),
                AfExternalProject.instance_code.label("project_name")
            )
            .join(CatTerm, AfErrorLog.severity_id == CatTerm.term_id)
            .outerjoin(
                AfExternalProject,
                AfErrorLog.source_system_id == AfExternalProject.external_project_id
            )
        )

        if search:
             query = query.filter(
                cast(AfErrorLog.err_id, String).ilike(f"%{search}%")
            )

        if severity:
            query = query.filter(
                CatTerm.code == severity,
                CatTerm.vocabulary.has(vocabulary_code="SEVERITY_GRADE")
            )

        if project:
            query = query.filter(
                AfExternalProject.instance_code.ilike(f"%{project}%")
            )

        if component:
            query = query.filter(AfErrorLog.component.ilike(f"%{component}%"))

        if error_code:
            query = query.filter(AfErrorLog.error_code.ilike(f"%{error_code}%"))

        if start_date:
            query = query.filter(AfErrorLog.at >= start_date)

        if end_date:
            query = query.filter(AfErrorLog.at <= end_date)

        total = query.count()

        errors = (
            query
            .order_by(AfErrorLog.at.desc())
            .offset((page_index - 1) * page_size)
            .limit(page_size)
            .all()
        )

        return errors, total
    
    def list_error_components(self, db: Session):
        """
        Obtiene los componentes registrados en los errores
        """

        components = (
            db.query(AfErrorLog.component)
            .distinct()
            .order_by(AfErrorLog.component.asc())
            .all()
        )

        return components
    
    def list_error_codes(self, db: Session):
        """
        Obtiene los códigos de error registrados
        """

        codes = (
            db.query(AfErrorLog.error_code)
            .distinct()
            .order_by(AfErrorLog.error_code.asc())
            .all()
        )

        return codes