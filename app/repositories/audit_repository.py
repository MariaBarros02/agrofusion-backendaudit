from app.models.af_external_projects import AfExternalProject
from typing import List
from fastapi import status
from app.core.errors import audit_error
from sqlalchemy.orm import Session
from app.models.af_error_log import AfErrorLog
from app.models.cat_terms import CatTerm
from app.schemas.audit import ErrorExtProRequest
from app.models.af_external_projects import AfExternalProject
import hashlib
import json
from datetime import datetime, date
from uuid import UUID
from  app.models.af_audit_log import AuditLog
from app.models.af_projects import Project


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

    

    def get_project_by_code(self, db: Session, *, code: str):
        """
        Obtiene un proyecto interno por su código único.

        :param db: Sesión activa de base de datos
        :param code: Código único del proyecto
        :return: Instancia de Project o None
        """
        return (
            db.query(Project)
            .filter(Project.code == code)
            .first()
        )

    
    def get_action_term_audit(self, db: Session, *, action_code: str) -> str:
        """
        Resuelve el term_id correspondiente a un action_code de auditoría.

        Busca el término dentro del vocabulario AUDIT_ACTION.

        :param db: Sesión activa de base de datos
        :param action_code: Código de acción (LOGIN_SUCCESS, OTP_FAILED, etc.)
        :return: UUID del término encontrado
        :raises RuntimeError: si el término no existe
        """
        term = (
            db.query(CatTerm)
            .join(CatTerm.vocabulary)
            .filter(
                CatTerm.code == action_code,
                CatTerm.vocabulary.has(vocabulary_code="AUDIT_ACTION")
            )
            .first()
        )

        if not term:
            raise RuntimeError(f"Audit action term not found: {action_code}")

        return term.term_id
    def log_event(
        self,
        db: Session,
        *,
        action_code: str,
        outcome: str,
        module_code: str,
        project_id,
        actor_id=None,
        session_id=None,
        ip: str | None = None,
        user_agent: str | None = None,
        metadata: dict | None = None,
        diff_json: dict | None = None,
    ) -> None:
        """
        Registra un evento genérico de auditoría.

        Usado para eventos no específicos de login:
        - Operaciones del sistema
        - Eventos administrativos
        - Acciones funcionales
        """

        # Payload del evento (metadata arbitraria)
        target_payload = metadata or {}

        hash_base = {
        "target": target_payload,
        "diff": diff_json,
        }

        # Generación del hash de integridad
        payload_str = json.dumps(hash_base, sort_keys=True)
        payload_hash = hashlib.sha256(payload_str.encode()).hexdigest()

        # Resolución del término de acción
        action_term_id = self.get_action_term_audit(db, action_code=action_code)


        # Construcción del registro de auditoría
        log = AuditLog(
            actor_id=actor_id,
            action_code=action_code,
            action_term_id=action_term_id,
            outcome=outcome,
            target_json=target_payload,
            diff_json=diff_json,
            actor_ip=ip,
            session_id=session_id,
            module_code=module_code,
            project_id=project_id,
            payload_hash=payload_hash,
            device_info={"user_agent": user_agent} if user_agent else None,
        )

        # Se agrega a la sesión (commit externo)
        db.add(log)
        db.commit()

    @staticmethod
    def model_to_dict(obj):
        data = {}
        for column in obj.__table__.columns:
            value = getattr(obj, column.name)

            if isinstance(value, (datetime, date)):
                value = value.isoformat()
            elif isinstance(value, UUID):
                value = str(value)

            data[column.name] = value

        return data