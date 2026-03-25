"""
Dependencias de autenticación y autorización.

Este módulo define dependencias de FastAPI para:
- Extraer y validar tokens Bearer
- Verificar sesiones activas
- Obtener el usuario autenticado actual
"""
from typing import List, Optional
from uuid import UUID

from fastapi import Depends, status, Request
#import requests
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from datetime import datetime, timezone
#from user_agents import parse
from app.core.database import get_db
from app.models.af_auth_tokens import AuthToken
from app.core.errors import audit_error
from app.core.security import decode_access_token
from app.models.af_roles import AfRole
from app.models.af_user_project_roles import AfUserProjectRole

# Esquema de autenticación Bearer para Swagger y validación automática de headers

security = HTTPBearer(auto_error=True)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    """
    Obtiene el usuario autenticado a partir del token Bearer, incluyendo su rol.

    Flujo de validación:
    1. Extrae el token del header Authorization
    2. Decodifica y valida el JWT
    3. Verifica que el token exista y no esté revocado en la base de datos
    4. Valida la sesión asociada al token
    5. Actualiza la última actividad de la sesión
    6. Obtiene el rol del usuario

    Args:
        credentials (HTTPAuthorizationCredentials): Credenciales Bearer.
        db (Session): Sesión de base de datos.

    Returns:
        dict: Información del contexto autenticado:
            - user: Usuario autenticado
            - session: Sesión activa
            - token: Registro del token
            - role: Información del rol (id y nombre)

    Raises:
        HTTPException: Si el token o la sesión no son válidos.
    """

    # Extracción del token JWT desde el header Authorization
    token = credentials.credentials

    # Decodificación y validación criptográfica del token JWT
    try:
        payload = decode_access_token(token)
    except Exception:
        raise audit_error(
            code="AUTH_INVALID_TOKEN",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    # Verificación del token en la base de datos (revocado o inexistente)
    token_db = (
        db.query(AuthToken)
        .filter(
            AuthToken.access_token == token,
            AuthToken.revoked_at.is_(None),
        )
        .first()
    )

    if not token_db:
        raise audit_error(
            code="AUTH_TOKEN_REVOKED",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    now = datetime.now(timezone.utc)

    # Validación de expiración del token de acceso
    if token_db.access_expires_at < now:
        raise audit_error(
            code="AUTH_TOKEN_EXPIRED",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    session = token_db.session

    # La sesión fue terminada explícitamente (logout, cierre forzado, etc.)
    if session.terminated_at is not None:
        raise audit_error(
            code="AUTH_SESSION_TERMINATED",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    if session.expires_at < now:
        raise audit_error(
            code="AUTH_SESSION_EXPIRED",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    
    # Actualizar última actividad de la sesión
    session.last_activity_at = datetime.now(timezone.utc)
    
    # Obtener información del rol del usuario
    role_info = get_user_role(db, session.user.user_id)
    
    db.commit()
    
    return {
        "user": session.user,
        "session": session,
        "token": token_db,
        "role": role_info  # Agregamos la información del rol
    }

def get_user_role(db: Session, user_id: int) -> dict | None:
    """
    Obtiene el rol de un usuario por su ID.
    
    :param db: Sesión activa de base de datos
    :param user_id: ID del usuario
    :return: Diccionario con id y nombre del rol, o None si no tiene rol
    """
    role_query = (
        db.query(
            AfRole.af_role_id.label("id"),
            AfRole.name.label("name"),
            AfRole.code.label("code"),
        )
        .join(AfUserProjectRole, AfUserProjectRole.af_role_id == AfRole.af_role_id)
        .filter(AfUserProjectRole.user_id == user_id)
        .first()
    )
    
    if not role_query:
        return None
    
    return {
        "id": role_query.id,
        "name": role_query.name,
        "code": role_query.code,
    }

def get_client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")

    if forwarded:
        return forwarded.split(",")[0].strip()

    return request.client.host


# def parse_device(user_agent: str | None):
#     if not user_agent:
#         return "Unknown device"

#     ua = parse(user_agent)

#     browser = ua.browser.family
#     os = ua.os.family
#     device = ua.device.family

#     if device == "Other":
#         device = "Desktop"

#     return f"{browser} en {os} ({device})"


# def get_location(ip: str | None):
#     if not ip:
#         return "Ubicación desconocida"

#     try:
#         res = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
#         data = res.json()

#         city = data.get("city")
#         region = data.get("region")
#         country = data.get("country")

#         parts = [p for p in [city, region, country] if p]

#         return ", ".join(parts) if parts else "Ubicación desconocida"

#     except Exception:
#         return "Ubicación desconocida"


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

