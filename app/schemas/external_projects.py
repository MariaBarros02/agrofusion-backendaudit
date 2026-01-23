"""
Schemas de respuesta para proyectos externos.

Define los modelos Pydantic utilizados para exponer información
de proyectos externos a través de la API.
"""


from pydantic import BaseModel
from uuid import UUID
from datetime import datetime
from typing import Optional


class ExternalProjectResponse(BaseModel):
    """
    Esquema de respuesta para proyectos externos.

    Representa la información pública de un proyecto externo
    expuesta a través de la API.
    """

    external_project_id: UUID
    """Identificador único del proyecto externo"""

    instance_code: Optional[str]
    """Código de instancia del proyecto externo"""


    project_name: Optional[str]
    """Nombre del proyecto externo"""


    client_name: Optional[str]
    """Nombre del cliente asociado al proyecto"""
    is_active: bool
    """Indica si el proyecto externo se encuentra activo"""

    # Configuración de Pydantic para compatibilidad con modelos ORM
    class Config:
        # Permite crear el schema a partir de modelos SQLAlchemy
        from_attributes = True  