from unittest.mock import MagicMock
from app.services.audit_service import AuditService


def test_register_errors_EP_calls_repo():
    """
    Test unitario del service AuditService.

    Verifica que:
    - El método register_errors_EP del service
      delega correctamente la lógica al repository
    - NO prueba lógica de DB (eso es responsabilidad del repo)
    """
    service = AuditService()
    service.audit_repo.register_errors_EP = MagicMock()

    fake_db = MagicMock()
    fake_errors = []

    service.register_errors_EP(fake_db, fake_errors)

    # Se verifica que el repo fue llamado con los parámetros correctos

    service.audit_repo.register_errors_EP.assert_called_once_with(
        db=fake_db,
        errors=fake_errors
    )
