"""
Utilidades de seguridad y autenticación.

Este módulo contiene funciones para:
- Creación y validación de tokens JWT
- Manejo de políticas de seguridad (bloqueos, expiraciones)
"""

from datetime import datetime, timedelta, timezone
from http.client import HTTPException

from fastapi import status

from jose import jwt, JWTError
from passlib.context import CryptContext
from app.core.config import settings
from datetime import timedelta




def decode_access_token(token: str) -> dict:
    """
    Decodifica y valida un token JWT de acceso.

    Realiza validaciones explícitas de:
    - Firma
    - Expiración
    - Integridad del token

    Args:
        token (str): Token JWT recibido.

    Returns:
        dict: Payload decodificado del token.

    Raises:
        HTTPException: Si el token es inválido o está expirado.
    """
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.algorithm]
        )

        # Validación explícita de exp
        exp = payload.get("exp")
        if exp is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token sin expiración"
            )

        if datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expirado"
            )

        return payload

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido"
        )
