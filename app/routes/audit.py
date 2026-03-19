from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List

from app.core.database import get_db
from app.schemas.audit import ErrorExtProRequest, ListAuditRequest, ListErrorsRequest
from app.services.audit_service import AuditService
from app.repositories.audit_repository import AuditRepository


router = APIRouter(prefix="/audit", tags=["Auditory"])


@router.post("/register-errors-EP")
def register_errors_EP(
    payload: List[ErrorExtProRequest],
    db: Session = Depends(get_db)
):
    service = AuditService()
    return service.register_errors_EP(db=db, errors=payload)


@router.post("/list")
def list_audit_logs(
    request: ListAuditRequest,
    db: Session = Depends(get_db),
    
):
    service = AuditService()

    return service.get_audit_logs(
        db=db,
        
        page_index=request.page_index,
        page_size=request.page_size,
        search=request.search,
        origin=request.origin,
        result=request.result,
        user_id=request.user_id,
        event_type=request.event_type,
        start_date=request.start_date,
        end_date=request.end_date
    )


@router.get("/users")
def list_users(
    db: Session = Depends(get_db),
    repository: AuditRepository = Depends(AuditRepository)
):
    users = repository.list_users(db)

    return [
        {
            "id": str(user.user_id),
            "name": user.name
        }
        for user in users
    ]


@router.get("/origins")
def list_origins(
    db: Session = Depends(get_db),
    repository: AuditRepository = Depends(AuditRepository)
):
    origins = repository.list_origins(db)

    return [
        {
            "code": origin.module_code
        }
        for origin in origins
    ]


@router.get("/events")
def list_events(
    db: Session = Depends(get_db),
    repository: AuditRepository = Depends(AuditRepository)
):
    events = repository.list_events(db)

    return [
        {
            "code": event.action_code
        }
        for event in events
    ]


@router.get("/results")
def list_results(
    db: Session = Depends(get_db),
    repository: AuditRepository = Depends(AuditRepository)
):
    results = repository.list_results(db)

    return [
        {
            "code": result.outcome
        }
        for result in results
    ]


@router.post("/errors/list")
def list_errors_EP(
    request: ListErrorsRequest,
    db: Session = Depends(get_db),
    
):
    service = AuditService()

    return service.get_errors_EP(
        db=db,
        
        page_index=request.page_index,
        page_size=request.page_size,
        search=request.search,
        severity=request.severity,
        project=request.project,
        component=request.component,
        error_code=request.error_code,  # 👈 importante (te faltaba)
        start_date=request.start_date,
        end_date=request.end_date
    )


@router.get("/errors/components")
def list_error_components(
    db: Session = Depends(get_db),
    service: AuditService = Depends(AuditService)
):
    components = service.get_error_components(db)

    return [
        {"code": component.component}
        for component in components
        if component.component
    ]


@router.get("/errors/codes")
def list_error_codes(
    db: Session = Depends(get_db),
    service: AuditService = Depends(AuditService)
):
    codes = service.get_error_codes(db)

    return [
        {"code": code.error_code}
        for code in codes
        if code.error_code
    ]