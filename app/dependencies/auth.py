"""
Dependencias de autenticación y autorización.

Este módulo define dependencias de FastAPI para:
- Extraer y validar tokens Bearer
- Obtener el usuario autenticado actual
"""
from fastapi import Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import Optional, List
from uuid import UUID

from app.core.database import get_db
from app.core.errors import audit_error
from app.core.config import settings
from jose import jwt, JWTError
from datetime import datetime, timezone

# Esquema de autenticación Bearer para Swagger y validación automática de headers
security = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db),
) -> Optional[dict]:
    """
    Obtiene el usuario autenticado a partir del token Bearer.

    Flujo de validación:
    1. Extrae el token del header Authorization
    2. Decodifica y valida el JWT
    3. Retorna el payload del token con información del usuario

    Args:
        credentials (HTTPAuthorizationCredentials): Credenciales Bearer (opcional).
        db (Session): Sesión de base de datos.

    Returns:
        dict: Payload del token JWT decodificado con información del usuario.
            - sub: ID del usuario (UUID como string)
            - Otros claims del token

    Raises:
        HTTPException: Si el token no es válido o está expirado.
    """
    if not credentials:
        # Si no hay token, retornar None (para desarrollo)
        # En producción, esto debería lanzar un error
        return None

    # Extracción del token JWT desde el header Authorization
    token = credentials.credentials

    # Decodificación y validación criptográfica del token JWT
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.algorithm]
        )

        # Validación explícita de exp
        exp = payload.get("exp")
        if exp is None:
            raise audit_error(
                code="AUTH_TOKEN_NO_EXPIRATION",
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        if datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc):
            raise audit_error(
                code="AUTH_TOKEN_EXPIRED",
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        return payload

    except JWTError:
        raise audit_error(
            code="AUTH_INVALID_TOKEN",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )


def get_current_user_id(
    current_user: Optional[dict] = Depends(get_current_user),
) -> Optional[UUID]:
    """
    Extrae el ID del usuario actual desde el token JWT.

    Args:
        current_user (dict): Payload del token JWT obtenido de get_current_user.

    Returns:
        Optional[UUID]: ID del usuario como UUID, o None si no hay usuario autenticado.
    """
    if not current_user:
        return None

    # El campo 'sub' del JWT contiene el user_id
    user_id_str = current_user.get("sub")
    if not user_id_str:
        return None

    try:
        return UUID(user_id_str)
    except (ValueError, TypeError):
        return None


def require_permission(required_code: str):
    """
    Crea una dependencia que exige que el usuario autenticado tenga
    un permiso específico identificado por su código.

    Se asume que el JWT incluye una claim ``permissions`` con una lista
    de códigos de permiso (por ejemplo: ["024", "026", "028"]).
    """

    def _dependency(current_user: Optional[dict] = Depends(get_current_user)) -> dict:
        if not current_user:
            raise audit_error(
                code="AUTH_NOT_AUTHENTICATED",
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        permissions: List[str] = current_user.get("permissions", []) or []

        if required_code not in permissions:
            raise audit_error(
                code="AUTH_INSUFFICIENT_PERMISSIONS",
                status_code=status.HTTP_403_FORBIDDEN,
                meta={"required_permission": required_code},
            )

        return current_user

    return _dependency

