from app.models.af_external_projects import AfExternalProject
from typing import List
from fastapi import status
from app.core.errors import audit_error
from sqlalchemy.orm import Session, aliased
from app.models.af_error_log import AfErrorLog
from app.models.cat_terms import CatTerm
from app.schemas.audit import ErrorExtProRequest

from app.models.af_audit_log import AuditLog
from app.models.users import Users
from app.models.cat_vocabularies import CatVocabulary

from app.models.af_projects import Project
from app.models.af_user_project_roles import AfUserProjectRole

import uuid
import hashlib
import json

from datetime import datetime, date
from uuid import UUID

from sqlalchemy import func, cast, String, or_, and_

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

    def resolve_audit_export_tenant_id(self, db: Session) -> UUID:
        """
        af_audit_exports.tenant_id referencia af_external_projects.external_project_id
        (FK af_audit_exports_tenant_fkey), no af_projects.
        """
        ep = self.get_EP_by_code(db, "AGROFUSION")
        if ep and ep.is_active:
            return ep.external_project_id
        row = (
            db.query(AfExternalProject)
            .filter(AfExternalProject.is_active.is_(True))
            .order_by(AfExternalProject.instance_code.asc())
            .first()
        )
        if not row:
            audit_error("INTERNAL_SERVER_ERROR", status.HTTP_500_INTERNAL_SERVER_ERROR)
        return row.external_project_id


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
                db.query(
                    AuditLog,
                    Users.name,
                    CatTerm.label,
                    CatTerm.description
                )
                .outerjoin(Users, Users.user_id == AuditLog.actor_id)
                .outerjoin(CatTerm, CatTerm.code == AuditLog.action_code) 
            )

            if search:
                query = query.filter(
                    cast(AuditLog.audit_id, String).ilike(f"%{search}%")
                )

            if origin:
                query = query.filter(AuditLog.module_code == origin)

            if result:
                query = query.filter(func.lower(AuditLog.outcome) == result.lower())

            if user_id:
                query = query.filter(AuditLog.actor_id == uuid.UUID(user_id))

            if event_type:
                query = query.filter(AuditLog.action_code == event_type)

            if start_date:
                query = query.filter(AuditLog.created_at >= start_date)

            if end_date:
                query = query.filter(AuditLog.created_at <= end_date)


            total = query.count()

            logs = (
                query
                .order_by(AuditLog.created_at.desc())
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
        db.query(AuditLog.module_code)
        .distinct()
        .order_by(AuditLog.module_code.asc())
        .all()
        )

        return origins
    
    def list_events(self, db: Session):
        """
        Obtiene los tipos de eventos registrados en la auditoría
        """

        events = (
       db.query(
            AuditLog.action_code,
            CatTerm.label
        ).join(
            CatTerm,
            CatTerm.term_id == AuditLog.action_term_id
        ).join(
            CatVocabulary,
            CatVocabulary.vocabulary_id == CatTerm.vocabulary_id
        ).filter(
            CatVocabulary.vocabulary_code == "AUDIT_ACTION"
        ).distinct().order_by(AuditLog.action_code.asc()).all()
    )

        return events
    
    def list_results(self, db: Session):
        """
        Obtiene los resultados disponibles en la auditoría
        """

        results = (
            db.query(AuditLog.outcome)
            .distinct()
            .order_by(AuditLog.outcome.asc())
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

    def get_project_by_id(self, db: Session, *, project_id: UUID):
        """
        Obtiene un proyecto por su UUID (af_project_id).

        :return: Instancia de Project o None
        """
        return (
            db.query(Project)
            .filter(Project.af_project_id == project_id)
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

    def log_event_optional_term(
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
        Registra un evento de auditoría sin fallar si el término AUDIT_ACTION no existe en catálogo.
        Útil para ciclos de vida de exportación (EXPORT_*) cuando no hay migración de datos de catálogo.
        """
        target_payload = metadata or {}
        hash_base = {
            "target": target_payload,
            "diff": diff_json,
        }
        payload_str = json.dumps(hash_base, sort_keys=True)
        payload_hash = hashlib.sha256(payload_str.encode()).hexdigest()

        action_term_id = None
        try:
            action_term_id = self.get_action_term_audit(db, action_code=action_code)
        except RuntimeError:
            pass

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
        db.add(log)
        db.commit()

    def get_user_visible_project_ids(self, db: Session, user_id: UUID) -> List[UUID]:
        rows = (
            db.query(AfUserProjectRole.af_project_id)
            .filter(AfUserProjectRole.user_id == user_id)
            .distinct()
            .all()
        )
        return [r[0] for r in rows]

    def _normalize_outcome_filters(self, outcomes: List[str] | None) -> List[str] | None:
        if not outcomes:
            return None
        mapped = []
        for o in outcomes:
            lo = (o or "").lower()
            if lo in ("failed", "error", "failure"):
                mapped.append("failure")
            elif lo == "success":
                mapped.append("success")
            else:
                mapped.append(lo)
        return list(dict.fromkeys(mapped))

    def build_audit_export_query(
        self,
        db: Session,
        *,
        visible_project_ids: List[UUID],
        search: str | None = None,
        date_from=None,
        date_to=None,
        user_ids: List[UUID] | None = None,
        project_ids_filter: List[UUID] | None = None,
        module_codes: List[str] | None = None,
        action_codes: List[str] | None = None,
        outcomes: List[str] | None = None,
        entity_types: List[str] | None = None,
    ):
        """
        Construye la consulta base para exportación (sin paginación), restringida a proyectos visibles.
        """
        action_term = aliased(CatTerm)
        query = (
            db.query(
                AuditLog,
                Users.email.label("actor_email"),
                Users.name.label("actor_name"),
                action_term.label.label("action_label"),
            )
            .outerjoin(Users, Users.user_id == AuditLog.actor_id)
            .outerjoin(action_term, action_term.term_id == AuditLog.action_term_id)
        )

        if not visible_project_ids:
            query = query.filter(False)
            return query

        allowed = set(visible_project_ids)
        if project_ids_filter:
            filt = {UUID(str(x)) for x in project_ids_filter}
            allowed = allowed & filt
        if not allowed:
            query = query.filter(False)
            return query

        query = query.filter(
            or_(
                AuditLog.project_id.in_(list(allowed)),
                AuditLog.project_id.is_(None),
            )
        )

        if search:
            query = query.filter(cast(AuditLog.audit_id, String).ilike(f"%{search}%"))

        if date_from:
            query = query.filter(AuditLog.created_at >= date_from)
        if date_to:
            query = query.filter(AuditLog.created_at <= date_to)

        if user_ids:
            query = query.filter(AuditLog.actor_id.in_(user_ids))

        if module_codes:
            query = query.filter(AuditLog.module_code.in_(module_codes))

        if action_codes:
            query = query.filter(AuditLog.action_code.in_(action_codes))

        norm_out = self._normalize_outcome_filters(outcomes)
        if norm_out:
            query = query.filter(func.lower(AuditLog.outcome).in_([o.lower() for o in norm_out]))

        if entity_types:
            query = query.filter(
                and_(
                    AuditLog.target_json.isnot(None),
                    AuditLog.target_json["entity_type"].astext.in_(entity_types),
                )
            )

        return query

    def count_audit_export(self, db: Session, base_query) -> int:
        return base_query.with_entities(AuditLog.audit_id).distinct().count()

    def fetch_audit_export_batch(
        self,
        db: Session,
        base_query,
        offset: int,
        limit: int,
    ):
        return (
            base_query.order_by(AuditLog.created_at.asc(), AuditLog.audit_id.asc())
            .offset(offset)
            .limit(limit)
            .all()
        )

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
