import pytest
from sqlalchemy.orm import Session
from app.repositories.audit_repository import AuditRepository
from app.models.cat_terms import CatTerm
from app.models.af_external_projects import AfExternalProject
from app.schemas.audit import ErrorExtProRequest
from app.core.errors import audit_error

@pytest.fixture
def audit_repo():
    """
    Fixture que instancia el repositorio de auditoría.
    """
    return AuditRepository()

def test_get_term_by_code(db: Session, audit_repo):
    """
    Verifica que get_term_by_code:
    - Retorna un término existente
    - Solo si está habilitado (is_enabled = True)
    """
    term = CatTerm(code="LOGIN_SUCCESS", is_enabled=True)
    db.add(term)
    db.commit()

    result = audit_repo.get_term_by_code(db, "LOGIN_SUCCESS")
    assert result is not None
    assert result.code == "LOGIN_SUCCESS"


def test_get_active_external_projects(db: Session, audit_repo):
    """
    Verifica que get_active_ext_pro:
    - Retorna únicamente proyectos activos
    """
    ep = AfExternalProject(
        instance_code="DISRIEGO",
        is_active=True
    )
    db.add(ep)
    db.commit()

    result = audit_repo.get_active_ext_pro(db)
    codes = [r.instance_code for r in result]

    assert "DISRIEGO" in codes


def test_register_errors_EP_success(db: Session, audit_repo):
    """
    Verifica que register_errors_EP:
    - Inserta correctamente un registro en af_error_log
    - Cuando context y severity existen
    """
    
    context = CatTerm(code="RESET_PASSWORD", is_enabled=True)
    severity = CatTerm(code="HIGH", is_enabled=True)

    db.add_all([context, severity])
    db.commit()

    error = ErrorExtProRequest(
        context="LOGIN_SSO_FAILED",
        severity="HIGH",
        project="SIGMA",
        message="Error test",
        payload_excerpt={"key": "value"},
        error_code="E001",
        component="audit"
    )

    audit_repo.register_errors_EP(db, [error])

    from app.models.af_error_log import AfErrorLog
    logs = db.query(AfErrorLog).all()
    assert len(logs) == 1

def test_register_errors_EP_context_not_found(db: Session, audit_repo):
    """
    Verifica que register_errors_EP:
    - Lanza una excepción cuando el context no existe
    """
    
    severity = CatTerm(code="HIGH", is_enabled=True)
    db.add(severity)
    db.commit()

    error = ErrorExtProRequest(
        context="LOGIN_SSO_FAILED",
        severity="HIGH",
        project="SIGMA",
        message="Error test",
        payload_excerpt={},
        error_code="E001",
        component="audit"
    )

    with pytest.raises(audit_error):
        audit_repo.register_errors_EP(db, [error])
