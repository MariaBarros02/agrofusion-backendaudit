from unittest.mock import patch

def test_register_errors_EP_endpoint(client):
    """
    Test de integración del endpoint:
    POST /audit/register-errors-EP

    Verifica que:
    - El endpoint acepta un payload válido
    - Responde con un status HTTP exitoso
    """
    payload = [
        {
            "context": "CTX",
            "severity": "HIGH",
            "project": None,
            "message": "Error desde API",
            "payload_excerpt": {"x": 1},
            "error_code": "E002",
            "component": "api"
        }
    ]

    with patch(
        "app.routes.audit.AuditService.register_errors_EP",
        return_value=None
    ):
        response = client.post(
            "/audit/register-errors-EP",
            json=payload
        )

    assert response.status_code in [200, 204]

