from pydantic import BaseModel
from typing import Dict
from typing import Optional

class ErrorExtProRequest(BaseModel):
    """
    Schema que representa un error enviado por un proyecto externo.

    Se utiliza para validar y documentar la información recibida
    desde sistemas externos a través del endpoint de auditoría.
    """

    context: str
    """Código del contexto donde ocurrió el error"""

    severity: str
    """Nivel de severidad del error (ej. LOW, MEDIUM, HIGH)"""

    project: Optional[str]
    """Código del proyecto externo que originó el error"""

    message: str
    """Mensaje descriptivo del error"""

    payload_excerpt: Optional[dict]
    """Fragmento del payload original que causó el error"""

    error_code: Optional[str]
    """Código interno o externo del error"""

    component: Optional[str]
    """Componente del sistema donde se produjo el error"""

