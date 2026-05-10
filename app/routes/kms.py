"""
Rutas para el módulo KMS (Key Management Service).

Endpoints para gestión de claves criptográficas, firmas digitales,
validación y rotación de claves.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from typing import List, Optional
from app.services.permissions_service import PermissionsService
from uuid import UUID
import traceback

from app.core.database import get_db
from app.services.kms_service import KmsService
from app.services.kms_ca_service import KmsCaService
from app.schemas.kms import (
    KeyCreateRequest,
    KeyResponse,
    KeyPublicInfoResponse,
    CertificateResponse,
    SignatureCreateRequest,
    SignatureResponse,
    SignatureVerifyRequest,
    SignatureVerifyResponse,
    SignatureValidationFriendlyResponse,
    SignatureTechnicalDetails,
    SignatureQueryItem,
    SignatureQueryDetail,
    SignatureQueryResponse,
    KmsAuditEventItem,
    KmsAuditEventsResponse,
    KeyRotationRequest,
    KeyRotationResponse,
    KeyListResponse,
    SignatureListResponse,
    CaRootInitRequest,
    CaRootResponse,
    CaRootCertificateResponse,
    RevokeRequest,
    RevokeResponse,
)
from app.models.users import Users
from app.models.af_kms_signatures import HashAlgorithm
from app.models.af_kms_signature_validations import AfKmsSignatureValidation
from app.models.af_audit_log import AuditLog
from sqlalchemy import cast, func, or_, String
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from datetime import datetime
from app.core.errors import audit_error
from app.dependencies.auth import get_current_user_id, get_current_user
from fastapi import status
from app.repositories.audit_repository import AuditRepository

router = APIRouter(prefix="/kms", tags=["KMS - Key Management Service"])


def _auth_responses(required_permission_code: str) -> dict:
    """
    Respuestas estandarizadas de autenticación/autorización para Swagger.
    """
    return {
        401: {
            "description": "No autenticado (token faltante, inválido o expirado)",
            "content": {
                "application/json": {
                    "examples": {
                        "not_authenticated": {
                            "summary": "Token no enviado",
                            "value": {
                                "detail": {
                                    "code": "AUTH_NOT_AUTHENTICATED",
                                    "meta": {},
                                }
                            },
                        },
                        "invalid_token": {
                            "summary": "Token inválido",
                            "value": {
                                "detail": {
                                    "code": "AUTH_INVALID_TOKEN",
                                    "meta": {},
                                }
                            },
                        },
                        "token_expired": {
                            "summary": "Token expirado",
                            "value": {
                                "detail": {
                                    "code": "AUTH_TOKEN_EXPIRED",
                                    "meta": {},
                                }
                            },
                        },
                    }
                }
            },
        },
        403: {
            "description": "Autorización fallida (permisos insuficientes)",
            "content": {
                "application/json": {
                    "examples": {
                        "insufficient_permissions": {
                            "summary": "Permiso requerido no presente en el token",
                            "value": {
                                "detail": {
                                    "code": "AUTH_INSUFFICIENT_PERMISSIONS",
                                    "meta": {"required_permission": required_permission_code},
                                }
                            },
                        }
                    }
                }
            },
        },
    }


def _token_validation_responses() -> dict:
    """
    Respuestas cuando el endpoint acepta token opcional (no exige permiso),
    pero valida el JWT si el cliente envía `Authorization: Bearer ...`.
    """
    return {
        401: {
            "description": "Token inválido/expirado o sin expiración válida",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_token": {
                            "summary": "AUTH_INVALID_TOKEN",
                            "value": {
                                "detail": {"code": "AUTH_INVALID_TOKEN", "meta": {}}
                            },
                        },
                        "token_expired": {
                            "summary": "AUTH_TOKEN_EXPIRED",
                            "value": {
                                "detail": {"code": "AUTH_TOKEN_EXPIRED", "meta": {}}
                            },
                        },
                        "no_exp": {
                            "summary": "AUTH_TOKEN_NO_EXPIRATION",
                            "value": {
                                "detail": {
                                    "code": "AUTH_TOKEN_NO_EXPIRATION",
                                    "meta": {},
                                }
                            },
                        },
                    },
                }
            },
        }
    }


def _log_kms_event(
    db: Session,
    *,
    request: Request,
    actor_id: Optional[UUID],
    action_code: str,
    metadata: Optional[dict] = None,
    outcome: str = "success",
) -> None:
    """
    Registra auditoría para operaciones KMS sin interrumpir la operación principal
    en caso de fallos de catálogo/configuración de auditoría.

    Usa ``log_event_optional_term`` para que los códigos nuevos del módulo KMS
    (``KMS_KEY_CREATED``, ``KMS_CERT_CREATED``, ``KMS_KEY_ROTATED``,
    ``KMS_CERT_VALIDATED``, ``KMS_ERR_INVALID_CERT``, etc.) se persistan en
    ``af_audit_log`` aunque el término aún no exista en el vocabulario
    ``AUDIT_ACTION`` de ``cat_term``. Si el término existe, igual se enlaza
    el ``action_term_id``.
    """
    service = KmsService()
    audit_repo = AuditRepository()
    try:
        project = service.get_agrofusion_project(db)
        audit_repo.log_event_optional_term(
            db=db,
            action_code=action_code,
            outcome=outcome,
            module_code="KMS",
            project_id=project.af_project_id,
            actor_id=actor_id,
            ip=request.client.host if request and request.client else None,
            user_agent=request.headers.get("user-agent") if request else None,
            metadata=metadata or {},
        )
    except Exception as audit_exc:
        # Último recurso: si falla por alguna otra razón (FK, conexión, etc.)
        # evitamos romper la operación principal y dejamos traza en stdout.
        try:
            db.rollback()
        except Exception:
            pass
        print(f"[AUDIT_WARN] {action_code}: {audit_exc}")


# ==================== Endpoints de Claves ====================

@router.post(
    "/keys",
    response_model=KeyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Crear nueva clave criptográfica",
    description="Genera un nuevo par de claves criptográficas y lo registra en el KMS bajo el proyecto AGROFUSION.",
    responses={
        **_auth_responses("026"),
        201: {
            "description": "Clave creada exitosamente",
            "content": {
                "application/json": {
                    "examples": {
                        "key_created": {
                            "summary": "Ejemplo de KeyResponse",
                            "value": {
                                "key_id": "123e4567-e89b-12d3-a456-426614174000",
                                "project_id": "223e4567-e89b-12d3-a456-426614174001",
                                "key_alias": "alias-demo",
                                "algorithm": "RSA_2048",
                                "key_length": 2048,
                                "key_purpose": "signing",
                                "key_fingerprint": "f00dbabe...",
                                "kms_key_reference": None,
                                "status": "ACTIVE",
                                "key_version": 1,
                                "valid_from": "2026-03-19T10:00:00Z",
                                "valid_to": "2027-03-19T10:00:00Z",
                                "created_by": "323e4567-e89b-12d3-a456-426614174002",
                                "created_at": "2026-03-19T10:00:00Z",
                                "rotated_at": None,
                                "supersedes_key_id": None,
                                "grace_period_end": None,
                            },
                        }
                    }
                }
            },
        },
        400: {
            "description": "Datos inválidos o conflicto con el estado/alias de la clave",
            "content": {
                "application/json": {
                    "examples": {
                        "key_alias_exists": {
                            "summary": "Alias ya existe en el proyecto",
                            "value": {
                                "detail": {"code": "KEY_ALIAS_EXISTS", "meta": {"key_alias": "alias-demo"}}
                            },
                        },
                        "duplicate_fingerprint": {
                            "summary": "Huella digital duplicada",
                            "value": {"detail": {"code": "DUPLICATE_KEY_FINGERPRINT", "meta": {}}},
                        },
                        "ca_root_not_found": {
                            "summary": "Precondición RF-INT-11 sin cumplir: no hay Root CA activa",
                            "value": {
                                "detail": {
                                    "code": "CA_ROOT_NOT_FOUND",
                                    "meta": {"error": "No existe una Root CA activa. Inicialícela antes de crear claves."},
                                }
                            },
                        },
                        "invalid_algorithm": {
                            "summary": "Algoritmo prohibido por RF-INT-12",
                            "value": {
                                "detail": {"code": "INVALID_KEY_ALGORITHM", "meta": {"algorithm": "RSA-1024"}}
                            },
                        },
                    }
                }
            },
        },
        409: {
            "description": "Ya existe una clave activa para la combinación (project_id, key_purpose)",
            "content": {
                "application/json": {
                    "examples": {
                        "active_key_already_exists": {
                            "summary": "ACTIVE_KEY_ALREADY_EXISTS",
                            "value": {
                                "detail": {
                                    "code": "ACTIVE_KEY_ALREADY_EXISTS",
                                    "meta": {
                                        "project_id": "223e4567-e89b-12d3-a456-426614174001",
                                        "key_purpose": "signing",
                                        "existing_key_id": "123e4567-e89b-12d3-a456-426614174000",
                                    },
                                }
                            },
                        }
                    }
                }
            },
        },
        404: {
            "description": "Proyecto no encontrado (project_id inexistente en el body)",
            "content": {
                "application/json": {
                    "examples": {
                        "project_not_found": {
                            "summary": "Proyecto inexistente",
                            "value": {"detail": "Proyecto no encontrado"},
                        }
                    }
                }
            },
        },
        500: {
            "description": "Error inesperado al crear la clave",
            "content": {
                "application/json": {
                    "examples": {
                        "key_creation_failed": {
                            "summary": "KEY_CREATION_FAILED",
                            "value": {"detail": {"code": "KEY_CREATION_FAILED", "meta": {"error": "..."}}},
                        }
                    }
                }
            },
        },
    },
)
def create_key(
    infoRequest: Request,
    request: KeyCreateRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    current_user_id: Optional[UUID] = Depends(get_current_user_id),
):
    """
    Crea una nueva clave criptográfica.

    Requiere permisos de administrador (KMS_ADMIN o AUDIT_SECURITY).
    La clave privada se almacena de forma segura en el KMS.
    Si el body incluye ``project_id``, debe corresponder a un proyecto existente;
    si no, se responde 404 con el mensaje ``Proyecto no encontrado``.
    Si se omite ``project_id``, la clave se asocia al proyecto interno AGROFUSION.
    """

    
    perm_service =  PermissionsService()

    if not perm_service.validate_permission(
            db, 
            current_user.get('role'), 
            "026"  # Código del permiso para crear una clave criptografica
    ):
        audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)

    service = KmsService()
    if request.project_id is not None:
        project = service.audit_repo.get_project_by_id(db, project_id=request.project_id)
        if project is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Proyecto no encontrado")
        project_id = project.af_project_id
    else:
        project_id = service.get_agrofusion_project(db).af_project_id

    try:

        key = service.create_key(
            db=db,
            project_id=project_id,
            key_alias=request.key_alias,
            algorithm=request.algorithm,
            key_purpose=request.key_purpose,
            valid_to=request.valid_to,
            created_by=current_user_id,
        )
        
        _log_kms_event(
            db=db,
            request=infoRequest,
            actor_id=current_user_id,
            action_code="KMS_KEY_CREATED",
            metadata={
                "key_id": str(key.key_id),
                "project_id": str(key.project_id),
                "key_alias": key.key_alias,
                "algorithm": request.algorithm.value if hasattr(request.algorithm, "value") else str(request.algorithm),
                "key_length": key.key_length,
                "key_purpose": key.key_purpose.value if hasattr(key.key_purpose, "value") else str(key.key_purpose),
                "key_fingerprint": key.key_fingerprint,
                "key_version": key.key_version,
            },
        )

        # RF-INT-14: auditar la emisión automática del certificado X.509
        # generado internamente por KmsService.create_key al invocar a
        # KmsCaService.issue_certificate_for_key.
        issued_cert = service.kms_repo.get_active_certificate_by_key_id(db, key.key_id)
        if issued_cert is not None:
            _log_kms_event(
                db=db,
                request=infoRequest,
                actor_id=current_user_id,
                action_code="KMS_CERT_CREATED",
                metadata={
                    "certificate_id": str(issued_cert.certificate_id),
                    "key_id": str(key.key_id),
                    "key_version": key.key_version,
                    "serial_number": issued_cert.serial_number,
                    "fingerprint": issued_cert.fingerprint,
                    "signature_algorithm": issued_cert.signature_algorithm,
                    "subject": issued_cert.subject,
                    "issuer": issued_cert.issuer,
                    "valid_from": issued_cert.valid_from.isoformat() if issued_cert.valid_from else None,
                    "valid_to": issued_cert.valid_to.isoformat() if issued_cert.valid_to else None,
                    "status": issued_cert.status,
                },
            )

        return key
    except HTTPException:
        raise
    except Exception as e:
        raise audit_error("KEY_CREATION_FAILED", status.HTTP_500_INTERNAL_SERVER_ERROR, {"error": str(e)})


@router.get(
    "/keys/{key_id}",
    response_model=KeyPublicInfoResponse,
    summary="Obtener información de una clave",
    description="Obtiene información pública de una clave criptográfica.",
    responses={
        **_auth_responses("027"),
        200: {
            "description": "Información pública de la clave",
            "content": {
                "application/json": {
                    "examples": {
                        "key_public_info": {
                            "summary": "Ejemplo de KeyPublicInfoResponse",
                            "value": {
                                "key_id": "123e4567-e89b-12d3-a456-426614174000",
                                "key_alias": "alias-demo",
                                "algorithm": "RSA_2048",
                                "key_length": 2048,
                                "key_purpose": "signing",
                                "key_fingerprint": "f00dbabe...",
                                "status": "ACTIVE",
                                "key_version": 1,
                                "valid_from": "2026-03-19T10:00:00Z",
                                "valid_to": "2027-03-19T10:00:00Z",
                                "public_key": "-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----",
                            },
                        }
                    }
                }
            },
        },
        404: {
            "description": "Clave no encontrada",
            "content": {
                "application/json": {
                    "examples": {
                        "key_not_found": {
                            "summary": "KEY_NOT_FOUND",
                            "value": {"detail": {"code": "KEY_NOT_FOUND", "meta": {}}},
                        }
                    }
                }
            },
        },
    },
)
def get_key(
    key_id: UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)

):
    """Obtiene información pública de una clave (sin datos sensibles)."""
    
    perm_service =  PermissionsService()

    if not perm_service.validate_permission(
            db, 
            current_user.get('role'), 
            "027"  # Código del permiso para listar una clave criptografica
    ):
        audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)

    
    service = KmsService()
    key = service.kms_repo.get_key_by_id(db, key_id)
    
    if not key:
        raise audit_error("KEY_NOT_FOUND", status.HTTP_404_NOT_FOUND)
    
    return key


@router.get(
    "/keys",
    response_model=KeyListResponse,
    summary="Listar claves de un proyecto",
    description="Obtiene todas las claves criptográficas de un proyecto.",
    responses={
        **_auth_responses("027"),
        200: {
            "description": "Lista de claves",
            "content": {
                "application/json": {
                    "examples": {
                        "keys_list": {
                            "summary": "Ejemplo KeyListResponse",
                            "value": {
                                "keys": [],
                                "total": 0,
                            },
                        }
                    }
                }
            },
        },
        400: {
            "description": "Filtro de estado inválido",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_status": {
                            "summary": "INVALID_STATUS",
                            "value": {"detail": {"code": "INVALID_STATUS", "meta": {}}},
                        }
                    }
                }
            },
        },
    },
)
def list_keys(
    project_id: Optional[UUID] = Query(
        None,
        description="ID del proyecto; si se omite, se usa el proyecto interno AGROFUSION",
    ),
    status_filter: Optional[str] = Query(None, description="Filtro por estado: active, rotated, revoked, expired"),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)

):
    """Lista las claves de un proyecto con filtros opcionales."""
    
    
    perm_service =  PermissionsService()

    if not perm_service.validate_permission(
            db, 
            current_user.get('role'), 
            "027"  # Código del permiso para listar claves criptograficas
    ):
        audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)

    
    service = KmsService()
    if project_id is None:
        project_id = service.get_agrofusion_project(db).af_project_id
    
    from app.models.af_kms_keys import KeyStatus
    status_enum = None
    if status_filter:
        try:
            status_enum = KeyStatus(status_filter)
        except ValueError:
            raise audit_error("INVALID_STATUS", status.HTTP_400_BAD_REQUEST)
    
    keys = service.kms_repo.get_keys_by_project(db, project_id, status_enum)
    
    return KeyListResponse(keys=keys, total=len(keys))


@router.get(
    "/keys/project/{project_id}/active",
    response_model=List[KeyPublicInfoResponse],
    summary="Obtener claves activas de un proyecto",
    description="Obtiene todas las claves activas y válidas de un proyecto.",
    responses={
        **_auth_responses("027"),
        200: {
            "description": "Claves activas del proyecto",
            "content": {
                "application/json": {
                    "examples": {
                        "active_keys": {
                            "summary": "Ejemplo lista de KeyPublicInfoResponse",
                            "value": [
                                {
                                    "key_id": "123e4567-e89b-12d3-a456-426614174000",
                                    "key_alias": "alias-demo",
                                    "algorithm": "RSA_2048",
                                    "key_length": 2048,
                                    "key_purpose": "signing",
                                    "key_fingerprint": "f00dbabe...",
                                    "status": "ACTIVE",
                                    "key_version": 1,
                                    "valid_from": "2026-03-19T10:00:00Z",
                                    "valid_to": "2027-03-19T10:00:00Z",
                                    "public_key": "-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----",
                                }
                            ],
                        }
                    }
                }
            },
        },
        400: {
            "description": "Propósito inválido",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_purpose": {
                            "summary": "INVALID_PURPOSE",
                            "value": {"detail": {"code": "INVALID_PURPOSE", "meta": {}}},
                        }
                    }
                }
            },
        },
    },
)
def get_active_keys(
    project_id: UUID,
    key_purpose: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)

):
    """Obtiene claves activas de un proyecto, opcionalmente filtradas por propósito."""
    
    perm_service =  PermissionsService()

    if not perm_service.validate_permission(
            db, 
            current_user.get('role'), 
            "027"  # Código del permiso para listar claves criptograficas
    ):
        audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)

    
    service = KmsService()
    
    from app.models.af_kms_keys import KeyPurpose
    purpose_enum = None
    if key_purpose:
        try:
            purpose_enum = KeyPurpose(key_purpose)
        except ValueError:
            raise audit_error("INVALID_PURPOSE", status.HTTP_400_BAD_REQUEST)
    
    keys = service.kms_repo.get_active_keys_by_project(db, project_id, purpose_enum)
    return keys


# ==================== Endpoints de Certificados ====================
#
# RF-INT-14: La emisión de certificados X.509 se ejecuta únicamente como una
# operación interna invocada automáticamente desde RF-INT-12 (creación de
# claves). Por esta razón NO se expone ningún endpoint público para crear
# certificados; solo endpoints de lectura.

@router.get(
    "/certificates/key/{key_id}",
    response_model=Optional[CertificateResponse],
    summary="Obtener certificado de una clave",
    description="Obtiene el certificado asociado a una clave. Retorna el certificado más reciente o `null` si no existe.",
    responses={
        **_token_validation_responses(),
        200: {
            "description": "Certificado encontrado o inexistente",
            "content": {
                "application/json": {
                    "examples": {
                        "certificate_found": {
                            "summary": "Certificado encontrado",
                            "value": {
                                "certificate_id": "123e4567-e89b-12d3-a456-426614174000",
                                "key_id": "123e4567-e89b-12d3-a456-426614174001",
                                "certificate_pem": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
                                "serial_number": "01AB23CD",
                                "subject": "CN=Demo",
                                "issuer": "CN=Demo CA",
                                "valid_from": "2026-03-19T10:00:00Z",
                                "valid_to": "2027-03-19T10:00:00Z",
                                "fingerprint": "aabbccddeeff...",
                                "issued_at": "2026-03-19T10:00:00Z",
                            },
                        },
                        "certificate_not_found": {
                            "summary": "Certificado no existe",
                            "value": None,
                        },
                    },
                }
            },
        }
    },
)
def get_certificate_by_key(
    key_id: UUID,
    db: Session = Depends(get_db),
    _current_user=Depends(get_current_user),
):
    """Obtiene el certificado más reciente asociado a una clave (requiere sesión autenticada)."""
    service = KmsService()
    certificate = service.kms_repo.get_certificate_by_key_id(db, key_id)
    return certificate


# ==================== Endpoints de Validación de Certificados (RF-INT-15) ====================

@router.get(
    "/certificates/{certificate_id}/validate",
    summary="Validar integridad de un certificado (RF-INT-15)",
    description=(
        "Valida la integridad, autenticidad y vigencia de un certificado X.509 "
        "emitido por la Root CA interna. Soporta dos modos (`mode` o `validation_mode`):\n\n"
        "- **current**: valida el estado presente del certificado.\n"
        "- **historical**: valida el estado que tenía el certificado en la fecha "
        "indicada por `reference_date` (obligatorio en este modo).\n\n"
        "Resultado: `valid` | `invalid` | `expired` | `revoked`."
    ),
    responses={
        **_token_validation_responses(),
        200: {
            "description": "Resultado de validación del certificado",
            "content": {
                "application/json": {
                    "examples": {
                        "valid": {
                            "summary": "Certificado válido",
                            "value": {
                                "result": "valid",
                                "reason": None,
                                "certificate_id": "123e4567-e89b-12d3-a456-426614174000",
                                "key_id": "123e4567-e89b-12d3-a456-426614174001",
                                "validation_mode": "current",
                                "reference_date": "2026-04-19T10:00:00+00:00",
                                "checked_at": "2026-04-19T10:00:00+00:00",
                                "fingerprint_ok": True,
                                "ca_signature_ok": True,
                                "period_ok": True,
                                "status_ok": True,
                            },
                        },
                        "revoked": {
                            "summary": "Certificado revocado",
                            "value": {
                                "result": "revoked",
                                "reason": "Certificate is revoked",
                                "certificate_id": "123e4567-e89b-12d3-a456-426614174000",
                                "key_id": "123e4567-e89b-12d3-a456-426614174001",
                                "validation_mode": "current",
                                "reference_date": "2026-04-19T10:00:00+00:00",
                                "checked_at": "2026-04-19T10:00:00+00:00",
                                "fingerprint_ok": True,
                                "ca_signature_ok": True,
                                "period_ok": True,
                                "status_ok": False,
                            },
                        },
                    }
                }
            },
        },
        400: {
            "description": "Parámetros inválidos",
            "content": {
                "application/json": {
                    "examples": {
                        "missing_reference_date": {
                            "summary": "HISTORICAL_REFERENCE_DATE_REQUIRED",
                            "value": {
                                "detail": {
                                    "code": "HISTORICAL_REFERENCE_DATE_REQUIRED",
                                    "meta": {},
                                }
                            },
                        }
                    }
                }
            },
        },
    },
)
def validate_certificate(
    infoRequest: Request,
    certificate_id: UUID,
    mode: Optional[str] = Query(
        None,
        description="Modo de validación: current | historical (por defecto current si no se envía ningún modo)",
    ),
    validation_mode: Optional[str] = Query(
        None,
        description="Sinónimo de `mode` (p. ej. matrices RF-INT-15 / clientes que envían validation_mode).",
    ),
    reference_date: Optional[str] = Query(
        None,
        description="Fecha ISO-8601 (obligatoria en modo historical)",
    ),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    current_user_id: Optional[UUID] = Depends(get_current_user_id),
):
    """
    Valida la integridad de un certificado (RF-INT-15).

    Deja traza del evento ``KMS_CERT_VALIDATED`` en ``af_audit_log``.
    """
    from app.services.kms_cert_validation_service import (
        CertificateValidationService,
        ValidationMode,
    )
    from datetime import datetime as _dt

    raw_mode = (validation_mode or "").strip() or (mode or "").strip() or "current"
    try:
        mode_enum = ValidationMode(raw_mode.lower())
    except ValueError:
        raise audit_error(
            "INVALID_VALIDATION_MODE",
            status.HTTP_400_BAD_REQUEST,
            {"mode": raw_mode, "allowed": ["current", "historical"]},
        )

    parsed_ref: Optional[_dt] = None
    if mode_enum == ValidationMode.HISTORICAL:
        if not reference_date:
            raise audit_error(
                "HISTORICAL_REFERENCE_DATE_REQUIRED",
                status.HTTP_400_BAD_REQUEST,
            )
        try:
            parsed_ref = _dt.fromisoformat(reference_date.replace("Z", "+00:00"))
        except ValueError:
            raise audit_error(
                "INVALID_REFERENCE_DATE",
                status.HTTP_400_BAD_REQUEST,
                {"reference_date": reference_date},
            )

    validator = CertificateValidationService()
    result = validator.validate_certificate(
        db,
        certificate_id=certificate_id,
        validation_mode=mode_enum,
        reference_date=parsed_ref,
    )

    _log_kms_event(
        db=db,
        request=infoRequest,
        actor_id=current_user_id,
        action_code="KMS_CERT_VALIDATED",
        metadata=result.to_dict(),
    )

    return result.to_dict()


# ==================== Endpoints de Firmas ====================

@router.post(
    "/signatures",
    response_model=SignatureResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Crear firma digital",
    description="Firma digitalmente un documento usando una clave del KMS.",
    responses={
        **_auth_responses("024"),
        201: {
            "description": "Firma creada correctamente",
            "content": {
                "application/json": {
                    "examples": {
                        "signature_created": {
                            "summary": "Ejemplo SignatureResponse",
                            "value": {
                                "signature_id": "123e4567-e89b-12d3-a456-426614174000",
                                "key_id": "123e4567-e89b-12d3-a456-426614174001",
                                "document_hash": "aabbccdd...",
                                "hash_algorithm": "SHA256",
                                "digital_signature": "BASE64_SIGNATURE...",
                                "signature_format": "PKCS7",
                                "signed_at": "2026-03-19T10:00:00Z",
                                "rfc3161_timestamp": None,
                                "document_id": None,
                                "document_type": None,
                                "signer_user_id": "323e4567-e89b-12d3-a456-426614174002",
                                "signing_reason": "Demo",
                                "project_id": "223e4567-e89b-12d3-a456-426614174003",
                                "created_at": "2026-03-19T10:00:00Z",
                            },
                        }
                    }
                }
            },
        },
        400: {
            "description": "Error validando clave/propósito o formato de hash",
            "content": {
                "application/json": {
                    "examples": {
                        "key_not_active": {
                            "summary": "KEY_NOT_ACTIVE",
                            "value": {"detail": {"code": "KEY_NOT_ACTIVE", "meta": {"status": "INACTIVE"}}},
                        },
                        "key_expired": {
                            "summary": "KEY_EXPIRED",
                            "value": {"detail": {"code": "KEY_EXPIRED", "meta": {}}},
                        },
                        "invalid_hash_format": {
                            "summary": "INVALID_HASH_FORMAT",
                            "value": {
                                "detail": {
                                    "code": "INVALID_HASH_FORMAT",
                                    "meta": {"error": "Hash inválido: ...", "hash_length": 3},
                                }
                            },
                        },
                        "key_purpose_invalid": {
                            "summary": "KEY_PURPOSE_INVALID",
                            "value": {"detail": {"code": "KEY_PURPOSE_INVALID", "meta": {"purpose": "encryption"}}},
                        },
                    }
                }
            },
        },
        404: {
            "description": "Clave no encontrada",
            "content": {
                "application/json": {
                    "examples": {
                        "key_not_found": {
                            "summary": "KEY_NOT_FOUND",
                            "value": {"detail": {"code": "KEY_NOT_FOUND", "meta": {}}},
                        }
                    }
                }
            },
        },
        500: {
            "description": "Error inesperado al crear la firma",
            "content": {
                "application/json": {
                    "examples": {
                        "signature_creation_failed": {
                            "summary": "SIGNATURE_CREATION_FAILED",
                            "value": {"detail": {"code": "SIGNATURE_CREATION_FAILED", "meta": {"error": "..."}}},
                        }
                    }
                }
            },
        },
    },
)
def create_signature(
    infoRequest: Request,
    request: SignatureCreateRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    current_user_id: Optional[UUID] = Depends(get_current_user_id),
):
    """
    Crea una firma digital de un documento.

    El documento debe ser hasheado previamente usando SHA-256, SHA-384 o SHA-512.
    La firma se realiza usando la clave privada almacenada en el KMS.
    """


    
    perm_service =  PermissionsService()

    if not perm_service.validate_permission(
            db, 
            current_user.get('role'), 
            "024"  # Código del permiso para crear firma digital
    ):
        audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)

    service = KmsService()
    try:
        # El formato de firma lo elige el sistema (RF-INT-16). No se acepta
        # desde el body.
        signature = service.sign_document(
            db=db,
            document_hash=request.document_hash,
            key_id=request.key_id,
            hash_algorithm=request.hash_algorithm,
            signature_format=None,
            include_timestamp=request.include_timestamp,
            document_id=request.document_id,
            document_type=request.document_type,
            signer_user_id=request.signer_user_id or current_user_id,
            signing_reason=request.signing_reason,
            project_id=None,  # Siempre None, se usará el de la clave
        )

        # RF-INT-16: auditar con action_code SIGNATURE_CREATED.
        _log_kms_event(
            db=db,
            request=infoRequest,
            actor_id=current_user_id,
            action_code="SIGNATURE_CREATED",
            metadata={
                "signature_id": str(signature.signature_id),
                "key_id": str(signature.key_id),
                "certificate_id": str(signature.certificate_id) if signature.certificate_id else None,
                "project_id": str(signature.project_id) if signature.project_id else None,
                "document_id": str(signature.document_id) if signature.document_id else None,
                "document_type": signature.document_type,
                "document_hash": signature.document_hash,
                "hash_algorithm": getattr(signature.hash_algorithm, "value", str(signature.hash_algorithm)),
                "signature_format": getattr(signature.signature_format, "value", str(signature.signature_format)),
                "signed_at": signature.signed_at.isoformat() if signature.signed_at else None,
            },
        )

        return signature
    except HTTPException as http_exc:
        # RF-INT-15: si la firma se aborta por certificado inválido, dejar
        # traza específica en auditoría con key_id, certificate_id, motivo
        # y timestamp antes de propagar el error al cliente.
        detail = http_exc.detail if isinstance(http_exc.detail, dict) else {}
        if detail.get("code") == "KMS_ERR_INVALID_CERT":
            meta = detail.get("meta", {}) or {}
            _log_kms_event(
                db=db,
                request=infoRequest,
                actor_id=current_user_id,
                action_code="KMS_ERR_INVALID_CERT",
                metadata={
                    "key_id": meta.get("key_id") or str(request.key_id),
                    "certificate_id": meta.get("certificate_id"),
                    "result": meta.get("result"),
                    "reason": meta.get("reason"),
                    "checked_at": meta.get("checked_at"),
                    "message": meta.get("message"),
                },
            )
        raise
    except Exception as e:
        import traceback
        print(f"Error creating signature: {str(e)}")
        print(traceback.format_exc())
        raise audit_error("SIGNATURE_CREATION_FAILED", status.HTTP_500_INTERNAL_SERVER_ERROR, {"error": str(e)})


@router.post(
    "/signatures/verify",
    response_model=SignatureVerifyResponse,
    summary="Validar firma digital",
    description="Valida una firma digital verificando su integridad criptográfica.",
    responses={
        **_auth_responses("028"),
        200: {
            "description": "Resultado de validación de firma",
            "content": {
                "application/json": {
                    "examples": {
                        "validation_valid": {
                            "summary": "Firma válida",
                            "value": {
                                "validation_id": "123e4567-e89b-12d3-a456-426614174000",
                                "signature_id": "123e4567-e89b-12d3-a456-426614174001",
                                "validation_result": "VALID",
                                "validation_reason": None,
                                "validated_by": "323e4567-e89b-12d3-a456-426614174002",
                                "validated_at": "2026-03-19T10:00:00Z",
                            },
                        },
                        "validation_invalid": {
                            "summary": "Firma inválida",
                            "value": {
                                "validation_id": "123e4567-e89b-12d3-a456-426614174003",
                                "signature_id": None,
                                "validation_result": "INVALID",
                                "validation_reason": "Cryptographic verification failed",
                                "validated_by": "323e4567-e89b-12d3-a456-426614174002",
                                "validated_at": "2026-03-19T10:00:00Z",
                            },
                        },
                    }
                }
            },
        },
        400: {
            "description": "Parámetros insuficientes para validar",
            "content": {
                "application/json": {
                    "examples": {
                        "key_id_required": {
                            "summary": "KEY_ID_REQUIRED",
                            "value": {"detail": {"code": "KEY_ID_REQUIRED", "meta": {}}},
                        }
                    }
                }
            },
        },
        404: {
            "description": "Firma o clave no encontrada",
            "content": {
                "application/json": {
                    "examples": {
                        "signature_not_found": {
                            "summary": "SIGNATURE_NOT_FOUND",
                            "value": {"detail": {"code": "SIGNATURE_NOT_FOUND", "meta": {}}},
                        },
                        "key_not_found": {
                            "summary": "KEY_NOT_FOUND",
                            "value": {"detail": {"code": "KEY_NOT_FOUND", "meta": {}}},
                        },
                    }
                }
            },
        },
        500: {
            "description": "Error inesperado al validar",
            "content": {
                "application/json": {
                    "examples": {
                        "signature_verification_failed": {
                            "summary": "SIGNATURE_VERIFICATION_FAILED",
                            "value": {"detail": {"code": "SIGNATURE_VERIFICATION_FAILED", "meta": {}}},
                        }
                    }
                }
            },
        },
    },
)
def verify_signature(
    infoRequest: Request,
    request: SignatureVerifyRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    current_user_id: Optional[UUID] = Depends(get_current_user_id),
):
    """
    Valida una firma digital.

    Verifica que la firma corresponda al hash del documento
    usando la clave pública asociada.
    """

    
    perm_service =  PermissionsService()

    if not perm_service.validate_permission(
            db, 
            current_user.get('role'), 
            "028"  # Código del permiso para verificar firma digital
    ):
        audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)

    service = KmsService()

    try:
        validation = service.verify_signature(
            db=db,
            document_hash=request.document_hash,
            document_content=request.document_content,
            digital_signature=request.digital_signature,
            signature_id=request.signature_id,
            key_id=request.key_id,
            hash_algorithm=request.hash_algorithm,
            validated_by=current_user_id,
        )

        # RF-INT-17: auditar resultado de la validación.
        signature_ref = request.signature_id or validation.signature_id
        sig_record = (
            service.kms_repo.get_signature_by_id(db, signature_ref)
            if signature_ref
            else None
        )
        _log_kms_event(
            db=db,
            request=infoRequest,
            actor_id=current_user_id,
            action_code="SIGNATURE_VALIDATED",
            metadata={
                "target_type": "kms_signature",
                "target_id": str(signature_ref) if signature_ref else None,
                "validation_id": str(validation.validation_id),
                "signature_id": str(validation.signature_id) if validation.signature_id else None,
                "validation_result": validation.validation_result,
                "validation_reason": validation.validation_reason,
                "key_id": str(sig_record.key_id) if sig_record else None,
                "certificate_id": (
                    str(sig_record.certificate_id)
                    if sig_record and sig_record.certificate_id
                    else None
                ),
                "signed_at": sig_record.signed_at.isoformat() if sig_record else None,
                "signature_format": (
                    sig_record.signature_format.value
                    if sig_record and hasattr(sig_record.signature_format, "value")
                    else (str(sig_record.signature_format) if sig_record else None)
                ),
                "validation_mode": "historical" if sig_record else "current",
            },
        )

        return validation
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise audit_error(
            "SIGNATURE_VERIFICATION_FAILED",
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            {"error": str(e)},
        )


# ==================== RF-INT-18: Presentación al usuario ====================

_VALIDATION_ESTADO_MAP = {
    "VALID": "Válida",
    "INVALID": "Inválida",
    "EXPIRED": "Expirada",
    "REVOKED": "Revocada",
}

_VALIDATION_DESCRIPCION_MAP = {
    "VALID": (
        "La firma es correcta y el documento no ha sido alterado desde el "
        "momento en que fue firmado."
    ),
    "INVALID": (
        "La firma no coincide con el documento o el documento ha sido "
        "modificado después de firmarse."
    ),
    "EXPIRED": (
        "El certificado asociado a la firma se encontraba fuera de su "
        "período de validez en el momento de firmar."
    ),
    "REVOKED": (
        "El certificado o la clave asociados a la firma fueron invalidados "
        "antes o durante el momento de la firma."
    ),
}


def _resolve_signer_display(db: Session, signer_user_id) -> tuple[Optional[str], Optional[str]]:
    """
    Resuelve el nombre y correo del firmante desde el módulo de usuarios.

    Devuelve (nombre, email). Si el usuario no existe, ambos serán ``None``.
    """
    if signer_user_id is None:
        return None, None
    try:
        user = db.query(Users).filter(Users.user_id == signer_user_id).first()
        if user is None:
            return None, None
        return user.name, user.email
    except Exception:
        return None, None


@router.post(
    "/signatures/{signature_id}/validate-presentable",
    response_model=SignatureValidationFriendlyResponse,
    summary="Validar firma y retornar resultado en lenguaje comprensible (RF-INT-18)",
    description=(
        "Inicia la validación de una firma digital (RF-INT-17) a partir únicamente "
        "de su `signature_id`, y retorna los resultados en lenguaje comprensible "
        "para el usuario final, incluyendo el nombre del firmante, la fecha de firma, "
        "el identificador del documento y el estado traducido "
        "(Válida / Inválida / Expirada / Revocada). Los datos técnicos se entregan "
        "en un bloque separado de solo lectura."
    ),
    responses={
        **_auth_responses("028"),
        200: {"description": "Resultado de validación presentable al usuario"},
        404: {"description": "Firma no encontrada"},
        500: {"description": "Error inesperado al validar"},
    },
)
def validate_signature_presentable(
    signature_id: UUID,
    infoRequest: Request,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    current_user_id: Optional[UUID] = Depends(get_current_user_id),
):
    """
    Endpoint orientado a la interfaz de usuario (RF-INT-18).

    Cumple los criterios de aceptación:
      * El usuario inicia la validación sin aportar datos técnicos.
      * El estado se muestra en lenguaje comprensible, no en códigos internos.
      * Los datos técnicos (hash, algoritmo, certificado) se incluyen como
        información de solo lectura.
      * El sistema completa automáticamente la información del firmante y
        del documento a partir de los registros internos.
    """

    perm_service = PermissionsService()
    if not perm_service.validate_permission(db, current_user.get("role"), "028"):
        audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)

    service = KmsService()

    try:
        validation = service.verify_signature(
            db=db,
            signature_id=signature_id,
            key_id=None,
            hash_algorithm=HashAlgorithm.SHA256,
            validated_by=current_user_id,
        )
    except HTTPException:
        raise
    except Exception as exc:
        traceback.print_exc()
        raise audit_error(
            "SIGNATURE_VERIFICATION_FAILED",
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            {"error": str(exc)},
        )

    signature_record = service.kms_repo.get_signature_by_id(db, signature_id)
    certificate_row = None
    if signature_record and signature_record.certificate_id:
        certificate_row = service.kms_repo.get_certificate_by_id(
            db, signature_record.certificate_id
        )

    signer_name, signer_email = _resolve_signer_display(
        db, signature_record.signer_user_id if signature_record else None
    )

    # ValidationResult guarda valores en minúsculas ("invalid", "valid", …);
    # los textos UI usan claves en MAYÚSCULAS.
    result_raw = (
        validation.validation_result.value
        if hasattr(validation.validation_result, "value")
        else str(validation.validation_result)
    )
    result_norm = str(result_raw).strip().upper()
    estado = _VALIDATION_ESTADO_MAP.get(result_norm, str(result_raw).title())
    resultado_general = _VALIDATION_DESCRIPCION_MAP.get(
        result_norm,
        "El sistema no pudo determinar de forma concluyente el estado de la firma.",
    )

    tech = SignatureTechnicalDetails(
        hash_documento=(signature_record.document_hash if signature_record else None),
        algoritmo_hash=(
            signature_record.hash_algorithm.value
            if signature_record and hasattr(signature_record.hash_algorithm, "value")
            else None
        ),
        formato_firma=(
            signature_record.signature_format.value
            if signature_record and hasattr(signature_record.signature_format, "value")
            else None
        ),
        certificate_id=(certificate_row.certificate_id if certificate_row else None),
        certificate_serial=(certificate_row.serial_number if certificate_row else None),
        certificate_fingerprint=(certificate_row.fingerprint if certificate_row else None),
        algoritmo_firma=(
            certificate_row.signature_algorithm if certificate_row else None
        ),
    )

    _log_kms_event(
        db=db,
        request=infoRequest,
        actor_id=current_user_id,
        action_code="SIGNATURE_VALIDATED",
        metadata={
            "target_type": "kms_signature",
            "target_id": str(signature_id),
            "validation_id": str(validation.validation_id),
            "signature_id": str(signature_id),
            "validation_result": result_norm,
            "estado_presentado": estado,
            "presentation_layer": True,
        },
    )

    return SignatureValidationFriendlyResponse(
        estado=estado,
        resultado_general=resultado_general,
        firmante=signer_name,
        firmante_email=signer_email,
        fecha_firma=(signature_record.signed_at if signature_record else None),
        identificador_documento=(
            signature_record.document_id if signature_record else None
        ),
        tipo_documento=(signature_record.document_type if signature_record else None),
        razon_firma=(signature_record.signing_reason if signature_record else None),
        validation_id=validation.validation_id,
        signature_id=signature_id,
        datos_tecnicos=tech,
    )


@router.get(
    "/signatures/query",
    response_model=SignatureQueryResponse,
    summary="Consultar firmas digitales (RF-INT-19)",
    description=(
        "Listado paginado de firmas digitales (af_kms_signatures) con filtros. "
        "Incluye opción `audit_export_only` para lotes de exportación de auditoría "
        "firmados (document_type=AUDIT_EXPORT). No expone el valor de la firma "
        "digital ni el contenido del certificado."
    ),
    responses={**_auth_responses("028")},
)
def query_signatures_rfint19(
    date_from: Optional[datetime] = Query(
        None, description="Fecha mínima de firma (signed_at >=)"
    ),
    date_to: Optional[datetime] = Query(
        None, description="Fecha máxima de firma (signed_at <=)"
    ),
    signer_user_id: Optional[UUID] = Query(
        None, description="Identificador del usuario firmante (UUID exacto)"
    ),
    signer_name: Optional[str] = Query(
        None, description="Búsqueda por nombre de usuario (users.name, subcadena)"
    ),
    q: Optional[str] = Query(
        None,
        description="Texto en ID de firma, documento, hash o nombre de exportación",
    ),
    key_algorithm: Optional[str] = Query(
        None, description="Subcadena del algoritmo de clave (ej. RSA, ECDSA)",
    ),
    document_type: Optional[str] = Query(
        None, description="Tipo de documento firmado (omitir si audit_export_only=true)"
    ),
    audit_export_only: bool = Query(
        False,
        description="Solo firmas de exportación de auditoría (AUDIT_EXPORT)",
    ),
    validation_status: Optional[str] = Query(
        None,
        description="Estado: valid | invalid | expired | revoked | unknown",
    ),
    limit: int = Query(10, ge=1, le=100, description="Tamaño de página"),
    offset: int = Query(0, ge=0, description="Registros a saltar (paginación)"),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    RF-INT-19 — Consulta paginada de firmas digitales.

    IMPORTANTE: esta ruta está declarada ANTES de ``/signatures/{signature_id}``
    porque FastAPI resuelve rutas en orden de registro. Si se declarara
    después, el segmento ``"query"`` se intentaría parsear como UUID y se
    devolvería 422 ``INVALID_UUID``.
    """
    perm_service = PermissionsService()
    if not perm_service.validate_permission(db, current_user.get("role"), "028"):
        audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)

    if validation_status and validation_status.lower() not in _VALIDATION_STATUS_ALLOWED:
        raise audit_error(
            "INVALID_VALIDATION_STATUS",
            status.HTTP_400_BAD_REQUEST,
            {"allowed": sorted(_VALIDATION_STATUS_ALLOWED)},
        )

    service = KmsService()
    rows, total = service.kms_repo.search_signatures_rfint19(
        db,
        date_from=date_from,
        date_to=date_to,
        signer_user_id=signer_user_id,
        signer_name=signer_name,
        search_q=q,
        document_type=document_type,
        audit_export_only=False,
        key_algorithm=key_algorithm,
        validation_status=validation_status,
        limit=limit,
        offset=offset,
    )

    items = [_signature_row_to_query_item(r) for r in rows]
    return SignatureQueryResponse(
        items=items,
        total_count=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/signatures/{signature_id}",
    response_model=SignatureResponse,
    summary="Obtener información de una firma",
    description="Obtiene información detallada de una firma digital.",
    responses={
        **_auth_responses("028"),
        200: {
            "description": "Información detallada de la firma",
            "content": {
                "application/json": {
                    "examples": {
                        "signature_details": {
                            "summary": "Ejemplo SignatureResponse",
                            "value": {
                                "signature_id": "123e4567-e89b-12d3-a456-426614174000",
                                "key_id": "123e4567-e89b-12d3-a456-426614174001",
                                "document_hash": "aabbccdd...",
                                "hash_algorithm": "SHA256",
                                "digital_signature": "BASE64_SIGNATURE...",
                                "signature_format": "PKCS7",
                                "signed_at": "2026-03-19T10:00:00Z",
                                "rfc3161_timestamp": None,
                                "document_id": None,
                                "document_type": None,
                                "signer_user_id": "323e4567-e89b-12d3-a456-426614174002",
                                "signing_reason": "Demo",
                                "project_id": "223e4567-e89b-12d3-a456-426614174003",
                                "created_at": "2026-03-19T10:00:00Z",
                            },
                        }
                    }
                }
            },
        },
        404: {
            "description": "Firma no encontrada",
            "content": {
                "application/json": {
                    "examples": {
                        "signature_not_found": {
                            "summary": "SIGNATURE_NOT_FOUND",
                            "value": {"detail": {"code": "SIGNATURE_NOT_FOUND", "meta": {}}},
                        }
                    }
                }
            },
        },
    },
)
def get_signature(
    signature_id: UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)

):
    """Obtiene información de una firma digital."""

    
    perm_service =  PermissionsService()

    if not perm_service.validate_permission(
            db, 
            current_user.get('role'), 
            "028"  # Código del permiso para listar fitma digital
    ):
        audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)

    service = KmsService()
    signature = service.kms_repo.get_signature_by_id(db, signature_id)
    
    if not signature:
        raise audit_error("SIGNATURE_NOT_FOUND", status.HTTP_404_NOT_FOUND)
    
    return signature


@router.get(
    "/signatures",
    response_model=SignatureListResponse,
    summary="Listar firmas de un proyecto",
    description="Obtiene todas las firmas digitales de un proyecto con paginación.",
    responses={
        **_auth_responses("028"),
        200: {
            "description": "Lista de firmas",
            "content": {
                "application/json": {
                    "examples": {
                        "signatures_list": {
                            "summary": "Ejemplo SignatureListResponse",
                            "value": {"signatures": [], "total": 0},
                        }
                    }
                }
            },
        }
    },
)
def list_signatures(
    project_id: Optional[UUID] = Query(
        None,
        description="ID del proyecto; si se omite, se usa el proyecto interno AGROFUSION",
    ),
    limit: int = Query(100, ge=1, le=1000, description="Número máximo de resultados"),
    offset: int = Query(0, ge=0, description="Número de resultados a saltar"),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)

):
    """Lista las firmas de un proyecto con paginación."""

    
    perm_service =  PermissionsService()

    if not perm_service.validate_permission(
            db, 
            current_user.get('role'), 
            "028"  # Código del permiso para listar firma digital
    ):
        audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)

    service = KmsService()
    if project_id is None:
        project_id = service.get_agrofusion_project(db).af_project_id
    
    signatures = service.kms_repo.get_signatures_by_project(
        db, project_id, limit, offset
    )
    total = service.kms_repo.count_signatures_by_project(db, project_id)
    
    return SignatureListResponse(signatures=signatures, total=total)


@router.get(
    "/signatures/document/{document_id}",
    response_model=List[SignatureResponse],
    summary="Obtener firmas de un documento",
    description="Obtiene todas las firmas asociadas a un documento específico.",
    responses={
        **_auth_responses("028"),
        200: {
            "description": "Lista de firmas del documento",
            "content": {
                "application/json": {
                    "examples": {
                        "document_signatures": {
                            "summary": "Ejemplo lista de SignatureResponse",
                            "value": [],
                        }
                    }
                }
            },
        },
    },
)
def get_document_signatures(
    document_id: UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)

):
    """Obtiene todas las firmas de un documento."""

    
    perm_service =  PermissionsService()

    if not perm_service.validate_permission(
            db, 
            current_user.get('role'), 
            "028"  # Código del permiso para listar firmas por un documento
    ):
        audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)

    service = KmsService()
    signatures = service.kms_repo.get_signatures_by_document(db, document_id)
    return signatures


# ==================== Endpoints de Rotación ====================

@router.post(
    "/keys/{key_id}/rotate",
    response_model=KeyRotationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Rotar clave criptográfica (RF-INT-13)",
    description=(
        "Rota una clave criptográfica cumpliendo el ciclo de vida de RF-INT-13:\n\n"
        "- Valida que la clave esté en estado `active`.\n"
        "- Genera una nueva clave con el mismo algoritmo y propósito.\n"
        "- Incrementa `key_version` y enlaza la nueva clave con la anterior "
        "mediante `supersedes_key_id`.\n"
        "- Marca la clave anterior como `rotated` y registra `grace_period_end`.\n"
        "- Durante el período de gracia la clave `rotated` NO puede firmar pero "
        "sigue siendo válida para verificar firmas históricas.\n"
        "- Registra el evento de auditoría `KMS_KEY_ROTATED`."
    ),
    responses={
        **_auth_responses("025"),
        201: {
            "description": "Rotación realizada correctamente",
            "content": {
                "application/json": {
                    "examples": {
                        "key_rotated": {
                            "summary": "Ejemplo KeyRotationResponse",
                            "value": {
                                "rotation_id": "123e4567-e89b-12d3-a456-426614174000",
                                "old_key_id": "123e4567-e89b-12d3-a456-426614174001",
                                "new_key_id": "123e4567-e89b-12d3-a456-426614174002",
                                "rotation_reason": "manual",
                                "grace_period_days": 30,
                                "rotated_by": "323e4567-e89b-12d3-a456-426614174003",
                                "rotated_at": "2026-03-19T10:00:00Z",
                            },
                        }
                    }
                }
            },
        },
        400: {
            "description": "La clave no está activa",
            "content": {
                "application/json": {
                    "examples": {
                        "key_not_active": {
                            "summary": "KEY_NOT_ACTIVE",
                            "value": {"detail": {"code": "KEY_NOT_ACTIVE", "meta": {"status": "INACTIVE"}}},
                        }
                    }
                }
            },
        },
        404: {
            "description": "Clave no encontrada",
            "content": {
                "application/json": {
                    "examples": {
                        "key_not_found": {
                            "summary": "KEY_NOT_FOUND",
                            "value": {"detail": {"code": "KEY_NOT_FOUND", "meta": {}}},
                        }
                    }
                }
            },
        },
        500: {
            "description": "Error inesperado al rotar clave",
            "content": {
                "application/json": {
                    "examples": {
                        "key_rotation_failed": {
                            "summary": "KEY_ROTATION_FAILED",
                            "value": {"detail": {"code": "KEY_ROTATION_FAILED", "meta": {}}},
                        }
                    }
                }
            },
        },
    },
)
def rotate_key(
    infoRequest: Request,
    key_id: UUID,
    request: KeyRotationRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    current_user_id: Optional[UUID] = Depends(get_current_user_id),
):
    """
    Rota una clave criptográfica.

    Genera una nueva clave con los mismos parámetros y marca la anterior
    como rotada. Durante el período de gracia, la clave antigua puede
    seguir validando firmas existentes pero no crear nuevas.
    
    Requiere permisos de administrador (KMS_ADMIN o AUDIT_SECURITY).
    """

    
    perm_service =  PermissionsService()

    if not perm_service.validate_permission(
            db, 
            current_user.get('role'), 
            "025"  # Código del permiso para rotar clave criptografica
    ):
        audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)

    service = KmsService()
    try:
        rotation, new_key = service.rotate_key(
            db=db,
            key_id=key_id,
            rotation_reason=request.rotation_reason,
            grace_period_days=request.grace_period_days,
            rotated_by=current_user_id,
        )
        
        _log_kms_event(
            db=db,
            request=infoRequest,
            actor_id=current_user_id,
            action_code="KMS_KEY_ROTATED",
            metadata={
                "rotation_id": str(rotation.rotation_id),
                "old_key_id": str(key_id),
                "new_key_id": str(new_key.key_id),
                "new_key_version": new_key.key_version,
                "reason": request.rotation_reason.value if hasattr(request.rotation_reason, "value") else str(request.rotation_reason),
            },
        )
        
        return rotation
    except HTTPException:
        raise
    except Exception as e:
        raise audit_error("KEY_ROTATION_FAILED", status.HTTP_500_INTERNAL_SERVER_ERROR)


@router.get(
    "/keys/{key_id}/rotations",
    response_model=List[KeyRotationResponse],
    summary="Obtener historial de rotaciones",
    description="Obtiene el historial de rotaciones de una clave.",
    responses={
        **_auth_responses("025"),
        200: {
            "description": "Historial de rotaciones",
            "content": {
                "application/json": {
                    "examples": {
                        "rotations_list": {
                            "summary": "Ejemplo lista de KeyRotationResponse",
                            "value": [],
                        }
                    }
                }
            },
        }
    },
)
def get_key_rotations(
    infoRequest: Request,
    key_id: UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    current_user_id: Optional[UUID] = Depends(get_current_user_id),
):
    """Obtiene todas las rotaciones relacionadas con una clave."""

    
    perm_service =  PermissionsService()

    if not perm_service.validate_permission(
            db, 
            current_user.get('role'), 
            "025"  # Código del permiso para listar el historial de rotaciones de una clave
    ):
        audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)

    service = KmsService()
    rotations = service.kms_repo.get_rotations_by_key(db, key_id)
    return rotations


# ==================== Endpoints de Root CA (RF-INT-11) ====================

@router.post(
    "/ca-root",
    response_model=CaRootResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Inicializar la Root CA interna del sistema",
    description=(
        "Crea la Autoridad Certificadora Raíz autofirmada del sistema (RF-INT-11). "
        "Solo puede existir una Root CA activa al mismo tiempo. "
        "La clave privada se cifra con AES-256-GCM usando KMS_MASTER_KEY y nunca "
        "es retornada por el API."
    ),
    responses={
        **_auth_responses("026"),
        201: {
            "description": "Root CA creada correctamente",
        },
        400: {
            "description": "Parámetros inválidos para la Root CA",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_algorithm": {
                            "summary": "INVALID_CA_ALGORITHM",
                            "value": {
                                "detail": {
                                    "code": "INVALID_CA_ALGORITHM",
                                    "meta": {"algorithm": "MD5"},
                                }
                            },
                        },
                        "validity_too_short": {
                            "summary": "CA_ROOT_VALIDITY_TOO_SHORT",
                            "value": {
                                "detail": {
                                    "code": "CA_ROOT_VALIDITY_TOO_SHORT",
                                    "meta": {"validity_days": 365, "minimum_required": 3650},
                                }
                            },
                        },
                    }
                }
            },
        },
        409: {
            "description": "Ya existe una Root CA activa",
            "content": {
                "application/json": {
                    "examples": {
                        "already_exists": {
                            "summary": "CA_ROOT_ALREADY_EXISTS",
                            "value": {
                                "detail": {
                                    "code": "CA_ROOT_ALREADY_EXISTS",
                                    "meta": {"ca_id": "123e4567-e89b-12d3-a456-426614174000"},
                                }
                            },
                        }
                    }
                }
            },
        },
        500: {
            "description": "Error inesperado al generar la Root CA",
            "content": {
                "application/json": {
                    "examples": {
                        "creation_failed": {
                            "summary": "CA_ROOT_CREATION_FAILED",
                            "value": {
                                "detail": {
                                    "code": "CA_ROOT_CREATION_FAILED",
                                    "meta": {"error": "..."},
                                }
                            },
                        }
                    }
                }
            },
        },
    },
)
def init_ca_root(
    infoRequest: Request,
    request: CaRootInitRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    current_user_id: Optional[UUID] = Depends(get_current_user_id),
):
    """
    Inicializa la Root CA interna.

    Requiere permiso de administrador KMS (código 026, mismo que para crear
    una clave criptográfica). Registra el evento ``KMS_CA_CREATED`` en
    auditoría.
    """
    perm_service = PermissionsService()
    if not perm_service.validate_permission(
        db,
        current_user.get("role"),
        "026",
    ):
        audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)

    service = KmsCaService()
    try:
        ca = service.initialize_root_ca(
            db=db,
            algorithm=request.algorithm,
            subject=request.subject,
            validity_days=request.validity_days,
            created_by=current_user_id,
        )

        _log_kms_event(
            db=db,
            request=infoRequest,
            actor_id=current_user_id,
            action_code="KMS_CA_CREATED",
            metadata={
                "ca_id": str(ca.ca_id),
                "subject": ca.subject,
                "serial_number": ca.serial_number,
                "fingerprint": ca.fingerprint,
                "valid_to": ca.valid_to.isoformat() if ca.valid_to else None,
            },
        )
        return ca
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error initializing Root CA: {str(e)}")
        print(traceback.format_exc())
        raise audit_error(
            "CA_ROOT_CREATION_FAILED",
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            {"error": str(e)},
        )


@router.get(
    "/ca-root",
    response_model=CaRootResponse,
    summary="Obtener la Root CA activa",
    description="Retorna los metadatos de la Root CA activa del sistema (sin clave privada).",
    responses={
        **_auth_responses("027"),
        404: {
            "description": "No existe Root CA activa",
            "content": {
                "application/json": {
                    "examples": {
                        "not_found": {
                            "summary": "CA_ROOT_NOT_FOUND",
                            "value": {"detail": {"code": "CA_ROOT_NOT_FOUND", "meta": {}}},
                        }
                    }
                }
            },
        },
    },
)
def get_ca_root(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Devuelve los metadatos públicos de la Root CA activa."""
    perm_service = PermissionsService()
    if not perm_service.validate_permission(
        db,
        current_user.get("role"),
        "027",
    ):
        audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)

    service = KmsCaService()
    ca = service.get_active_ca(db)
    if ca is None:
        raise audit_error("CA_ROOT_NOT_FOUND", status.HTTP_404_NOT_FOUND)
    return ca


@router.get(
    "/ca-root/certificate",
    response_model=CaRootCertificateResponse,
    summary="Exportar el certificado público de la Root CA",
    description=(
        "Retorna el certificado X.509 v3 público de la Root CA activa en formato PEM, "
        "junto con su clave pública y metadatos esenciales. No requiere permisos de "
        "administración: cualquier cliente autenticado puede consumirlo para validar "
        "firmas emitidas por el sistema."
    ),
    responses={
        **_token_validation_responses(),
        404: {
            "description": "No existe Root CA activa",
            "content": {
                "application/json": {
                    "examples": {
                        "not_found": {
                            "summary": "CA_ROOT_NOT_FOUND",
                            "value": {"detail": {"code": "CA_ROOT_NOT_FOUND", "meta": {}}},
                        }
                    }
                }
            },
        },
    },
)
def export_ca_root_certificate(
    db: Session = Depends(get_db),
    _current_user=Depends(get_current_user),
):
    """Exporta el certificado público de la Root CA activa."""
    service = KmsCaService()
    ca = service.get_active_ca(db)
    if ca is None:
        raise audit_error("CA_ROOT_NOT_FOUND", status.HTTP_404_NOT_FOUND)
    return CaRootCertificateResponse(
        subject=ca.subject,
        issuer=ca.issuer,
        serial_number=ca.serial_number,
        fingerprint=ca.fingerprint,
        valid_from=ca.valid_from,
        valid_to=ca.valid_to,
        certificate_pem=ca.certificate_pem,
        public_key=ca.public_key,
    )


# ==================== RF-INT-19: Consulta y auditoría ====================

_KMS_AUDIT_ACTION_CODES = [
    "KMS_CA_CREATED",
    "KMS_KEY_CREATED",
    "KMS_KEY_ROTATED",
    "KMS_KEY_REVOKED",
    "KMS_CERT_CREATED",
    "KMS_CERT_REVOKED",
    "KMS_CERT_VALIDATED",
    "SIGNATURE_CREATED",
    "SIGNATURE_VALIDATED",
]

_VALIDATION_STATUS_ALLOWED = {"valid", "invalid", "expired", "revoked", "unknown"}


def _signature_row_to_query_item(row) -> SignatureQueryItem:
    """Mapea una fila de la búsqueda RF-INT-19 al schema público."""
    (
        sig,
        validation_status,
        expires_at,
        signer_name,
        key_algorithm,
        export_name,
    ) = row
    status_value = (validation_status or "unknown").lower()
    key_alg = None
    if key_algorithm is not None:
        key_alg = (
            key_algorithm.value
            if hasattr(key_algorithm, "value")
            else str(key_algorithm)
        )
    return SignatureQueryItem(
        signature_id=sig.signature_id,
        validation_status=status_value,
        signature_format=sig.signature_format,
        expires_at=expires_at,
        document_type=sig.document_type,
        signer_user_id=sig.signer_user_id,
        signer_name=signer_name,
        signed_at=sig.signed_at,
        document_id=sig.document_id,
        key_algorithm=key_alg,
        export_name=export_name,
    )


@router.get(
    "/signatures/{signature_id}/detail",
    response_model=SignatureQueryDetail,
    summary="Detalle funcional de una firma (RF-INT-19)",
    description=(
        "Detalle de una firma digital con atributos funcionales. No expone el "
        "valor ``digital_signature`` ni el contenido del certificado. Los "
        "identificadores ``key_id`` y ``certificate_id`` se incluyen para "
        "trazabilidad interna."
    ),
    responses={**_auth_responses("028"), 404: {"description": "Firma no encontrada"}},
)
def signature_detail_rfint19(
    signature_id: UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    perm_service = PermissionsService()
    if not perm_service.validate_permission(db, current_user.get("role"), "028"):
        audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)

    service = KmsService()
    sig = service.kms_repo.get_signature_by_id(db, signature_id)
    if sig is None:
        raise audit_error("SIGNATURE_NOT_FOUND", status.HTTP_404_NOT_FOUND)

    # Derivar el estado de la última validación.
    last_val = (
        db.query(AfKmsSignatureValidation)
        .filter(AfKmsSignatureValidation.signature_id == signature_id)
        .order_by(AfKmsSignatureValidation.validated_at.desc())
        .first()
    )
    validation_status = (
        (last_val.validation_result.value if hasattr(last_val.validation_result, "value") else str(last_val.validation_result))
        if last_val
        else "unknown"
    ).lower()

    # Certificado asociado (para expires_at)
    expires_at = None
    if sig.certificate_id:
        cert = service.kms_repo.get_certificate_by_id(db, sig.certificate_id)
        if cert:
            expires_at = cert.valid_to

    # Firmante (nombre)
    signer_name = None
    if sig.signer_user_id:
        user = db.query(Users).filter(Users.user_id == sig.signer_user_id).first()
        if user:
            signer_name = user.name

    key_alg_s = None
    if sig.key_id:
        from app.models.af_kms_keys import AfKmsKey as _K

        krow = db.query(_K).filter(_K.key_id == sig.key_id).first()
        if krow and krow.algorithm is not None:
            key_alg_s = (
                krow.algorithm.value
                if hasattr(krow.algorithm, "value")
                else str(krow.algorithm)
            )

    export_name = None
    if sig.document_id:
        from app.models.af_audit_exports import AfAuditExport as _E

        erow = (
            db.query(_E)
            .filter(_E.export_id == cast(sig.document_id, PGUUID(as_uuid=True)))
            .first()
        )
        if erow:
            export_name = erow.export_name

    return SignatureQueryDetail(
        signature_id=sig.signature_id,
        validation_status=validation_status,
        signature_format=sig.signature_format,
        expires_at=expires_at,
        document_type=sig.document_type,
        signer_user_id=sig.signer_user_id,
        signer_name=signer_name,
        signed_at=sig.signed_at,
        document_id=sig.document_id,
        key_algorithm=key_alg_s,
        export_name=export_name,
        document_hash=sig.document_hash,
        hash_algorithm=sig.hash_algorithm,
        signing_reason=sig.signing_reason,
        key_id=sig.key_id,
        certificate_id=sig.certificate_id,
    )


def _audit_row_to_event_item(row, user_name_map: dict) -> KmsAuditEventItem:
    """Convierte un ``AuditLog`` ORM en el item de respuesta RF-INT-19."""
    payload = row.target_json if isinstance(row.target_json, dict) else None
    target_type = None
    target_id = None
    if payload:
        target_type = payload.get("target_type")
        target_id = payload.get("target_id")
    return KmsAuditEventItem(
        audit_id=row.audit_id,
        action_code=row.action_code,
        actor_id=row.actor_id,
        actor_name=user_name_map.get(row.actor_id) if row.actor_id else None,
        created_at=row.created_at,
        outcome=row.outcome,
        target_type=target_type,
        target_id=target_id,
        metadata=payload,
    )


@router.get(
    "/signatures/{signature_id}/audit-trail",
    response_model=KmsAuditEventsResponse,
    summary="Eventos de auditoría asociados a una firma (RF-INT-19)",
    description=(
        "Devuelve los eventos del ``af_audit_log`` relacionados con la firma: "
        "su creación, validaciones y eventos de la clave / certificado "
        "subyacentes. Los registros son inmutables."
    ),
    responses={**_auth_responses("028"), 404: {"description": "Firma no encontrada"}},
)
def signature_audit_trail_rfint19(
    signature_id: UUID,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    perm_service = PermissionsService()
    if not perm_service.validate_permission(db, current_user.get("role"), "028"):
        audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)

    service = KmsService()
    sig = service.kms_repo.get_signature_by_id(db, signature_id)
    if sig is None:
        raise audit_error("SIGNATURE_NOT_FOUND", status.HTTP_404_NOT_FOUND)

    sig_id_str = str(sig.signature_id)
    key_id_str = str(sig.key_id) if sig.key_id else None
    cert_id_str = str(sig.certificate_id) if sig.certificate_id else None

    # Filtramos por acción KMS y por identificadores en target_json.
    q = db.query(AuditLog).filter(AuditLog.action_code.in_(_KMS_AUDIT_ACTION_CODES))

    wanted_ids = [sig_id_str]
    if key_id_str:
        wanted_ids.append(key_id_str)
    if cert_id_str:
        wanted_ids.append(cert_id_str)

    # Comparación textual sobre target_json serializado (portable y sin
    # depender de operadores JSON específicos del dialecto).
    or_clauses = [
        func.cast(AuditLog.target_json, String).ilike(f"%{wid}%") for wid in wanted_ids
    ]
    q = q.filter(or_(*or_clauses))

    total = q.with_entities(func.count(AuditLog.audit_id)).scalar() or 0
    rows = (
        q.order_by(AuditLog.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    # Resolver nombres de usuarios en un solo query.
    actor_ids = {r.actor_id for r in rows if r.actor_id}
    user_name_map: dict = {}
    if actor_ids:
        for u in db.query(Users).filter(Users.user_id.in_(actor_ids)).all():
            user_name_map[u.user_id] = u.name

    events = [_audit_row_to_event_item(r, user_name_map) for r in rows]
    return KmsAuditEventsResponse(
        events=events, total_count=int(total), limit=limit, offset=offset
    )


@router.get(
    "/audit-events",
    response_model=KmsAuditEventsResponse,
    summary="Consulta de eventos KMS en auditoría (RF-INT-19)",
    description=(
        "Listado paginado de eventos del módulo KMS registrados en "
        "``af_audit_log``. Incluye KMS_CA_CREATED, KMS_KEY_CREATED, "
        "KMS_KEY_ROTATED, KMS_KEY_REVOKED, KMS_CERT_CREATED, "
        "KMS_CERT_REVOKED, KMS_CERT_VALIDATED, SIGNATURE_CREATED y "
        "SIGNATURE_VALIDATED. Los registros son inmutables (INSERT/SELECT only)."
    ),
    responses={**_auth_responses("028")},
)
def list_kms_audit_events(
    action_code: Optional[str] = Query(
        None, description="Código de acción KMS (si se omite, incluye todos)"
    ),
    date_from: Optional[datetime] = Query(
        None, description="Fecha mínima del evento (created_at >=)"
    ),
    date_to: Optional[datetime] = Query(
        None, description="Fecha máxima del evento (created_at <=)"
    ),
    actor_id: Optional[UUID] = Query(
        None, description="Usuario que ejecutó la acción"
    ),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    perm_service = PermissionsService()
    if not perm_service.validate_permission(db, current_user.get("role"), "028"):
        audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)

    q = db.query(AuditLog).filter(AuditLog.action_code.in_(_KMS_AUDIT_ACTION_CODES))
    if action_code:
        if action_code not in _KMS_AUDIT_ACTION_CODES:
            raise audit_error(
                "INVALID_ACTION_CODE",
                status.HTTP_400_BAD_REQUEST,
                {"allowed": _KMS_AUDIT_ACTION_CODES},
            )
        q = q.filter(AuditLog.action_code == action_code)
    if date_from:
        q = q.filter(AuditLog.created_at >= date_from)
    if date_to:
        q = q.filter(AuditLog.created_at <= date_to)
    if actor_id:
        q = q.filter(AuditLog.actor_id == actor_id)

    total = q.with_entities(func.count(AuditLog.audit_id)).scalar() or 0
    rows = q.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit).all()

    actor_ids = {r.actor_id for r in rows if r.actor_id}
    user_name_map: dict = {}
    if actor_ids:
        for u in db.query(Users).filter(Users.user_id.in_(actor_ids)).all():
            user_name_map[u.user_id] = u.name

    events = [_audit_row_to_event_item(r, user_name_map) for r in rows]
    return KmsAuditEventsResponse(
        events=events, total_count=int(total), limit=limit, offset=offset
    )


# ==================== RF-INT-20: Revocación ====================

@router.post(
    "/keys/{key_id}/revoke",
    response_model=RevokeResponse,
    summary="Revocar clave criptográfica (RF-INT-20)",
    description=(
        "Revoca una clave criptográfica de forma transaccional e irreversible. "
        "Si la clave tiene un certificado activo asociado, también se revoca "
        "en la misma transacción. Registra un evento ``KMS_KEY_REVOKED`` y, "
        "cuando aplique, un evento ``KMS_CERT_REVOKED`` en ``af_audit_log``."
    ),
    responses={
        **_auth_responses("026"),
        404: {
            "description": "Clave no encontrada",
            "content": {
                "application/json": {
                    "examples": {
                        "key_not_found": {
                            "summary": "KEY_NOT_FOUND",
                            "value": {"detail": {"code": "KEY_NOT_FOUND", "meta": {}}},
                        }
                    }
                }
            },
        },
        409: {
            "description": "La clave ya se encuentra revocada",
            "content": {
                "application/json": {
                    "examples": {
                        "already_revoked": {
                            "summary": "KEY_ALREADY_REVOKED",
                            "value": {
                                "detail": {
                                    "code": "KEY_ALREADY_REVOKED",
                                    "meta": {"key_id": "..."},
                                }
                            },
                        }
                    }
                }
            },
        },
    },
)
def revoke_key(
    key_id: UUID,
    payload: RevokeRequest,
    infoRequest: Request,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    current_user_id: Optional[UUID] = Depends(get_current_user_id),
):
    """
    Revoca una clave criptográfica (RF-INT-20).

    - Precondiciones: usuario autenticado con permiso administrativo,
      la clave existe y no está previamente revocada.
    - Efecto: ``af_kms_keys.status = 'revoked'`` y, si aplica,
      ``af_kms_certificates.status = 'revoked'`` en la misma transacción.
    - Auditoría: emite ``KMS_KEY_REVOKED`` y, cuando aplique,
      ``KMS_CERT_REVOKED`` vinculado al certificado cascadeado.
    """
    perm_service = PermissionsService()
    if not perm_service.validate_permission(db, current_user.get("role"), "045"):
        audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)

    service = KmsService()
    result = service.revoke_key(
        db=db,
        key_id=key_id,
        reason=payload.reason.value,
        actor_id=current_user_id,
    )

    _log_kms_event(
        db=db,
        request=infoRequest,
        actor_id=current_user_id,
        action_code="KMS_KEY_REVOKED",
        metadata={
            "target_type": "key",
            "target_id": str(result["key_id"]),
            "key_id": str(result["key_id"]),
            "reason": payload.reason.value,
            "note": payload.note,
            "revoked_at": result["revoked_at"].isoformat(),
            "cascaded_certificate_id": (
                str(result["cascaded_certificate_id"])
                if result.get("cascaded_certificate_id")
                else None
            ),
        },
    )

    if result.get("cascaded_certificate_id"):
        _log_kms_event(
            db=db,
            request=infoRequest,
            actor_id=current_user_id,
            action_code="KMS_CERT_REVOKED",
            metadata={
                "target_type": "certificate",
                "target_id": str(result["cascaded_certificate_id"]),
                "certificate_id": str(result["cascaded_certificate_id"]),
                "key_id": str(result["key_id"]),
                "reason": payload.reason.value,
                "note": payload.note,
                "revoked_at": result["revoked_at"].isoformat(),
                "cascade_source": "key_revocation",
            },
        )

    return RevokeResponse(
        resource_type="key",
        resource_id=result["key_id"],
        status="revoked",
        revoked_at=result["revoked_at"],
        reason=payload.reason,
        cascaded_certificate_id=result.get("cascaded_certificate_id"),
        message="Clave revocada exitosamente",
    )


@router.post(
    "/certificates/{certificate_id}/revoke",
    response_model=RevokeResponse,
    summary="Revocar certificado digital (RF-INT-20)",
    description=(
        "Revoca un certificado digital de forma transaccional e irreversible. "
        "Actualiza ``af_kms_certificates.status = 'revoked'`` y registra un "
        "evento ``KMS_CERT_REVOKED`` en ``af_audit_log``."
    ),
    responses={
        **_auth_responses("026"),
        404: {
            "description": "Certificado no encontrado",
            "content": {
                "application/json": {
                    "examples": {
                        "cert_not_found": {
                            "summary": "CERTIFICATE_NOT_FOUND",
                            "value": {
                                "detail": {
                                    "code": "CERTIFICATE_NOT_FOUND",
                                    "meta": {},
                                }
                            },
                        }
                    }
                }
            },
        },
        409: {
            "description": "El certificado ya se encuentra revocado",
            "content": {
                "application/json": {
                    "examples": {
                        "already_revoked": {
                            "summary": "CERTIFICATE_ALREADY_REVOKED",
                            "value": {
                                "detail": {
                                    "code": "CERTIFICATE_ALREADY_REVOKED",
                                    "meta": {"certificate_id": "..."},
                                }
                            },
                        }
                    }
                }
            },
        },
    },
)
def revoke_certificate(
    certificate_id: UUID,
    payload: RevokeRequest,
    infoRequest: Request,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    current_user_id: Optional[UUID] = Depends(get_current_user_id),
):
    """
    Revoca un certificado digital (RF-INT-20).

    - Precondiciones: usuario autenticado con permiso administrativo,
      el certificado existe y no está previamente revocado.
    - Efecto: ``af_kms_certificates.status = 'revoked'`` y
      ``revoked_at`` se fija a la hora actual.
    - Auditoría: emite ``KMS_CERT_REVOKED``.
    """
    perm_service = PermissionsService()
    if not perm_service.validate_permission(db, current_user.get("role"), "026"):
        audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)

    service = KmsService()
    result = service.revoke_certificate(
        db=db,
        certificate_id=certificate_id,
        reason=payload.reason.value,
        actor_id=current_user_id,
    )

    _log_kms_event(
        db=db,
        request=infoRequest,
        actor_id=current_user_id,
        action_code="KMS_CERT_REVOKED",
        metadata={
            "target_type": "certificate",
            "target_id": str(result["certificate_id"]),
            "certificate_id": str(result["certificate_id"]),
            "key_id": str(result["key_id"]) if result.get("key_id") else None,
            "reason": payload.reason.value,
            "note": payload.note,
            "revoked_at": result["revoked_at"].isoformat(),
        },
    )

    return RevokeResponse(
        resource_type="certificate",
        resource_id=result["certificate_id"],
        status="revoked",
        revoked_at=result["revoked_at"],
        reason=payload.reason,
        message="Certificado revocado exitosamente",
    )
