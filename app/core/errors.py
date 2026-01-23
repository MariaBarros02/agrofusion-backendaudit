"""
Utilidades para manejo de errores HTTP estandarizados.

Este módulo define funciones para lanzar excepciones
con un formato consistente de error para la API.
"""

from fastapi import HTTPException
from typing import Optional, Dict, Any


def audit_error(code: str, status_code: int, meta: Optional[Dict[str, Any]] = None):
        """
        Lanza una excepción HTTP con un formato de error estandarizado.

        Args:
                code (str): Código interno del error.
                status_code (int): Código HTTP a retornar.
                meta (dict, opcional): Información adicional del error.

        Returns:
                None: Siempre lanza una excepción HTTP.
        """
        # Estructura del error que será enviada en la respuesta HTTP
        error_response = {"code": code, "meta": meta or {}}
        # Se lanza la excepción HTTP con el detalle del error
        raise HTTPException(status_code=status_code, detail=error_response)
