"""
Rutas para el módulo KMS (Key Management Service).

Endpoints para gestión de claves criptográficas, firmas digitales,
validación y rotación de claves.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from typing import List, Optional
from uuid import UUID
import hashlib
import traceback

from app.core.database import get_db
from app.services.kms_service import KmsService
from app.schemas.kms import (
    KeyCreateRequest,
    KeyResponse,
    KeyPublicInfoResponse,
    CertificateCreateRequest,
    CertificateResponse,
    SignatureCreateRequest,
    SignatureResponse,
    SignatureVerifyRequest,
    SignatureVerifyResponse,
    KeyRotationRequest,
    KeyRotationResponse,
    KeyListResponse,
    SignatureListResponse,
)
from app.core.errors import audit_error
from app.dependencies.auth import get_current_user_id, require_permission
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


# ==================== Endpoints de Claves ====================

@router.post(
    "/keys",
    response_model=KeyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Crear nueva clave criptográfica",
    description="Genera un nuevo par de claves criptográficas y lo registra en el KMS.",
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
    current_user=Depends(require_permission("026")),
    current_user_id: Optional[UUID] = Depends(get_current_user_id),
):
    """
    Crea una nueva clave criptográfica para un proyecto.

    Requiere permisos de administrador (KMS_ADMIN o AUDIT_SECURITY).
    La clave privada se almacena de forma segura en el KMS.
    """
    service = KmsService()
    audit_repo = AuditRepository()
    try:
        key = service.create_key(
            db=db,
            project_id=request.project_id,
            key_alias=request.key_alias,
            algorithm=request.algorithm,
            key_purpose=request.key_purpose,
            valid_to=request.valid_to,
            created_by=current_user_id,
        )
        
        # TODO: Registrar evento en af_audit_log
        audit_repo.log_event(
            db=db,
            action_code="CREATE_CRYPTOGRAPHIC_KEY",
            outcome="success",
            module_code="KMS",
            project_id=request.project_id,
            actor_id=current_user_id,
            ip=infoRequest.client.host,
            user_agent=infoRequest.headers.get("user-agent"),
            metadata={"key_id": str(key.key_id), "algorithm": request.algorithm.value}
        )
        
        return key
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        print(f"Error creating key: {str(e)}")
        print(traceback.format_exc())
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
    current_user=Depends(require_permission("027")),
):
    """Obtiene información pública de una clave (sin datos sensibles)."""
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
    project_id: UUID = Query(..., description="ID del proyecto"),
    status_filter: Optional[str] = Query(None, description="Filtro por estado: active, rotated, revoked, expired"),
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("027")),
):
    """Lista las claves de un proyecto con filtros opcionales."""
    service = KmsService()
    
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
    current_user=Depends(require_permission("027")),
):
    """Obtiene claves activas de un proyecto, opcionalmente filtradas por propósito."""
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

@router.post(
    "/certificates",
    response_model=CertificateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Registrar certificado X.509",
    description="Registra un certificado X.509 asociado a una clave existente del KMS.",
    responses={
        **_token_validation_responses(),
        201: {
            "description": "Certificado registrado correctamente",
            "content": {
                "application/json": {
                    "examples": {
                        "certificate_created": {
                            "summary": "Ejemplo CertificateResponse",
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
                        }
                    }
                }
            },
        },
        404: {
            "description": "Clave asociada no encontrada",
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
            "description": "Certificado duplicado (fingerprint repetido)",
            "content": {
                "application/json": {
                    "examples": {
                        "certificate_already_exists": {
                            "summary": "CERTIFICATE_ALREADY_EXISTS",
                            "value": {
                                "detail": {
                                    "code": "CERTIFICATE_ALREADY_EXISTS",
                                    "meta": {"error": "Un certificado con el mismo fingerprint ya existe"},
                                }
                            },
                        }
                    }
                }
            },
        },
        400: {
            "description": "Error al registrar el certificado",
            "content": {
                "application/json": {
                    "examples": {
                        "certificate_creation_failed": {
                            "summary": "CERTIFICATE_CREATION_FAILED (400)",
                            "value": {
                                "detail": {"code": "CERTIFICATE_CREATION_FAILED", "meta": {"error": "..."}}
                            },
                        }
                    }
                }
            },
        },
        500: {
            "description": "Error inesperado al registrar el certificado",
            "content": {
                "application/json": {
                    "examples": {
                        "certificate_creation_failed_500": {
                            "summary": "CERTIFICATE_CREATION_FAILED (500)",
                            "value": {
                                "detail": {"code": "CERTIFICATE_CREATION_FAILED", "meta": {"error": "..."}}
                            },
                        }
                    }
                }
            },
        },
    },
)
def create_certificate(
    request: CertificateCreateRequest,
    db: Session = Depends(get_db),
    current_user_id: Optional[UUID] = Depends(get_current_user_id),
):
    """Registra un certificado X.509 emitido por una CA."""
    service = KmsService()
    
    try:
        # Validar que la clave exista
        key = service.kms_repo.get_key_by_id(db, request.key_id)
        if not key:
            raise audit_error("KEY_NOT_FOUND", status.HTTP_404_NOT_FOUND)
        
        # Calcular fingerprint del certificado
        cert_bytes = request.certificate_pem.encode()
        fingerprint = hashlib.sha256(cert_bytes).hexdigest()
        
        certificate = service.kms_repo.create_certificate(
            db=db,
            key_id=request.key_id,
            certificate_pem=request.certificate_pem,
            serial_number=request.serial_number,
            subject=request.subject,
            issuer=request.issuer,
            valid_from=request.valid_from,
            valid_to=request.valid_to,
            fingerprint=fingerprint,
        )
        
        return certificate
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error creating certificate: {str(e)}")
        print(traceback.format_exc())
        
        # Manejar errores de integridad (duplicados, etc.)
        if isinstance(e, IntegrityError):
            db.rollback()
            error_msg = str(e.orig) if hasattr(e, 'orig') else str(e)
            if "fingerprint" in error_msg.lower() or "unique" in error_msg.lower():
                raise audit_error("CERTIFICATE_ALREADY_EXISTS", status.HTTP_409_CONFLICT, {"error": "Un certificado con el mismo fingerprint ya existe"})
            raise audit_error("CERTIFICATE_CREATION_FAILED", status.HTTP_400_BAD_REQUEST, {"error": error_msg})
        
        raise audit_error("CERTIFICATE_CREATION_FAILED", status.HTTP_500_INTERNAL_SERVER_ERROR, {"error": str(e)})


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
    current_user_id: Optional[UUID] = Depends(get_current_user_id),
):
    """Obtiene el certificado más reciente asociado a una clave."""
    service = KmsService()
    certificate = service.kms_repo.get_certificate_by_key_id(db, key_id)
    return certificate


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
    request: SignatureCreateRequest,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("024")),
    current_user_id: Optional[UUID] = Depends(get_current_user_id),
):
    """
    Crea una firma digital de un documento.

    El documento debe ser hasheado previamente usando SHA-256, SHA-384 o SHA-512.
    La firma se realiza usando la clave privada almacenada en el KMS.
    """
    service = KmsService()
    
    try:
        # No pasar project_id, el servicio lo obtendrá de la clave automáticamente
        signature = service.sign_document(
            db=db,
            document_hash=request.document_hash,
            key_id=request.key_id,
            hash_algorithm=request.hash_algorithm,
            signature_format=request.signature_format,
            include_timestamp=request.include_timestamp,
            document_id=request.document_id,
            document_type=request.document_type,
            signer_user_id=request.signer_user_id or current_user_id,
            signing_reason=request.signing_reason,
            project_id=None,  # Siempre None, se usará el de la clave
        )
        
        # TODO: Registrar evento en af_audit_log
        # audit_repo.log_event(
        #     db=db,
        #     action_code="SIGNATURE_CREATED",
        #     outcome="success",
        #     module_code="KMS",
        #     project_id=request.project_id,
        #     actor_id=current_user_id,
        #     metadata={"signature_id": str(signature.signature_id), "key_id": str(request.key_id)}
        # )
        
        return signature
    except HTTPException:
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
    request: SignatureVerifyRequest,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("028")),
    current_user_id: Optional[UUID] = Depends(get_current_user_id),
):
    """
    Valida una firma digital.

    Verifica que la firma corresponda al hash del documento
    usando la clave pública asociada.
    """
    service = KmsService()
    
    try:
        validation = service.verify_signature(
            db=db,
            document_hash=request.document_hash,
            digital_signature=request.digital_signature,
            signature_id=request.signature_id,
            key_id=request.key_id,
            hash_algorithm=request.hash_algorithm,
            validated_by=current_user_id,
        )
        
        # TODO: Registrar evento en af_audit_log
        # audit_repo.log_event(
        #     db=db,
        #     action_code=f"SIGNATURE_{validation.validation_result.upper()}",
        #     outcome="success" if validation.validation_result == "valid" else "failure",
        #     module_code="KMS",
        #     actor_id=current_user_id,
        #     metadata={"validation_id": str(validation.validation_id), "result": validation.validation_result}
        # )
        
        return validation
    except HTTPException:
        raise
    except Exception as e:
        raise audit_error("SIGNATURE_VERIFICATION_FAILED", status.HTTP_500_INTERNAL_SERVER_ERROR)


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
    current_user=Depends(require_permission("028")),
):
    """Obtiene información de una firma digital."""
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
    project_id: UUID = Query(..., description="ID del proyecto"),
    limit: int = Query(100, ge=1, le=1000, description="Número máximo de resultados"),
    offset: int = Query(0, ge=0, description="Número de resultados a saltar"),
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("028")),
):
    """Lista las firmas de un proyecto con paginación."""
    service = KmsService()
    
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
    current_user=Depends(require_permission("028")),
):
    """Obtiene todas las firmas de un documento."""
    service = KmsService()
    signatures = service.kms_repo.get_signatures_by_document(db, document_id)
    return signatures


# ==================== Endpoints de Rotación ====================

@router.post(
    "/keys/{key_id}/rotate",
    response_model=KeyRotationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Rotar clave criptográfica",
    description="Rota una clave criptográfica generando una nueva y marcando la anterior como rotada.",
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
    key_id: UUID,
    request: KeyRotationRequest,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("025")),
    current_user_id: Optional[UUID] = Depends(get_current_user_id),
):
    """
    Rota una clave criptográfica.

    Genera una nueva clave con los mismos parámetros y marca la anterior
    como rotada. Durante el período de gracia, la clave antigua puede
    seguir validando firmas existentes pero no crear nuevas.
    
    Requiere permisos de administrador (KMS_ADMIN o AUDIT_SECURITY).
    """
    service = KmsService()
    
    try:
        rotation, new_key = service.rotate_key(
            db=db,
            key_id=key_id,
            rotation_reason=request.rotation_reason,
            grace_period_days=request.grace_period_days,
            rotated_by=current_user_id,
        )
        
        # TODO: Registrar evento en af_audit_log
        # audit_repo.log_event(
        #     db=db,
        #     action_code="KMS_KEY_ROTATED",
        #     outcome="success",
        #     module_code="KMS",
        #     project_id=new_key.project_id,
        #     actor_id=current_user_id,
        #     metadata={
        #         "rotation_id": str(rotation.rotation_id),
        #         "old_key_id": str(key_id),
        #         "new_key_id": str(new_key.key_id),
        #         "reason": request.rotation_reason.value
        #     }
        # )
        
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
    key_id: UUID,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("025")),
):
    """Obtiene todas las rotaciones relacionadas con una clave."""
    service = KmsService()
    rotations = service.kms_repo.get_rotations_by_key(db, key_id)
    return rotations

