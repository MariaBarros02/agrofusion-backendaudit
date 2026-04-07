from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response, status
from fastapi.responses import FileResponse
from jose import JWTError
from sqlalchemy.orm import Session
from typing import List
from app.services.permissions_service import PermissionsService
from app.core.errors import audit_error

from app.dependencies.auth import get_current_user
from app.core.database import get_db
from app.core.config import settings
from app.core.security import decode_export_download_token
from app.schemas.audit import (
    AuditExportJobResponse,
    CreateAuditExportRequest,
    ErrorExtProRequest,
    ListAuditRequest,
    ListErrorsRequest,
)
from app.services.audit_service import AuditService
from app.repositories.audit_repository import AuditRepository
from app.services.audit_export_service import (
    create_audit_export_job,
    get_job_for_user,
    job_to_response,
    list_jobs_for_user,
)
from app.services.audit_export_store import job_store


router = APIRouter(prefix="/audit", tags=["Auditory"])



@router.post(
    "/register-errors-EP",
    response_model=None,
    status_code=status.HTTP_200_OK,
    summary="Registrar errores de proyectos externos",
    description=(
        "Recibe una lista de errores generados por proyectos externos y los almacena en el sistema de auditoría.\n\n"
        "El endpoint valida:\n"
        "- `context` contra el catálogo `SYSTEM_ACTION`\n"
        "- `severity` contra el catálogo `SEVERITY_GRADE`\n"
        "- `project` (opcional) contra el catálogo de proyectos externos activos\n\n"
        "Si todo es válido, persiste cada error en `af_error_log`."
    ),
    responses={
        200: {
            "description": "Errores registrados correctamente",
            "content": {
                "application/json": {
                    "examples": {
                        "ok": {"value": None}
                    }
                }
            },
        },
        404: {
            "description": "Contexto o severidad no encontrada en catálogos",
            "content": {
                "application/json": {
                    "examples": {
                        "context_not_found": {
                            "summary": "Contexto no existe",
                            "value": {"detail": {"code": "CONTEXT_NOT_FOUND", "meta": {}}},
                        },
                        "severity_not_found": {
                            "summary": "Severidad no existe",
                            "value": {"detail": {"code": "SEVERITY_NOT_FOUND", "meta": {}}},
                        },
                    }
                }
            },
        },
        400: {
            "description": "Error en la estructura del payload o validaciones",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_payload": {
                            "summary": "Estructura inválida",
                            "value": {
                                "detail": {
                                    "code": "INVALID_REQUEST_BODY",
                                    "meta": {
                                        "reason": "Estructura del payload incorrecta"
                                    }
                                }
                            }
                        },
                        "missing_fields": {
                            "summary": "Campos requeridos faltantes",
                            "value": {
                                "detail": {
                                    "code": "REQUIRED_FIELDS_MISSING",
                                    "meta": {
                                        "fields": ["project", "message", "severity"]
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        401: {
            "description": "Error de autenticación",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_token": {
                            "summary": "Token inválido o expirado",
                            "value": {
                                "detail": {
                                    "code": "AUTH_INVALID_TOKEN",
                                    "meta": {}
                                }
                            }
                        }
                    }
                }
            }
        },
        403: {
            "description": "Error de autorización",
            "content": {
                "application/json": {
                    "examples": {
                        "insufficient_permissions": {
                            "summary": "Permisos insuficientes",
                            "value": {
                                "detail": {
                                    "code": "AUTH_INSUFFICIENT_PERMISSIONS",
                                    "meta": {}
                                }
                            }
                        }
                    }
                }
            }
        },
        500: {
            "description": "Error interno del servidor",
            "content": {
                "application/json": {
                    "examples": {
                        "internal_error": {
                            "summary": "Error inesperado",
                            "value": {
                                "detail": {
                                    "code": "INTERNAL_SERVER_ERROR",
                                    "meta": {}
                                }
                            }
                        }
                    }
                }
            }
        },
    },
)
def register_errors_EP(payload: List[ErrorExtProRequest], db: Session = Depends(get_db)):
    """
    ### Registrar errores desde proyectos externos

    Recibe una lista de errores generados por proyectos externos y los almacena en el
    sistema de auditoría.

    **Flujo:**
    1. Valida `context` en el catálogo `SYSTEM_ACTION`
    2. Valida `severity` en el catálogo `SEVERITY_GRADE`
    3. Si `project` viene informado, valida que exista y sea un proyecto externo activo
    4. Persiste el error en `af_error_log`
    """
    service = AuditService()
    return service.register_errors_EP(db=db, errors=payload)

# ==================== AUDITORÍA ====================

@router.post(
    "/list",
    summary="Listar eventos de auditoría",
    description="Obtiene una lista paginada de eventos de auditoría del sistema con filtros dinámicos para análisis y trazabilidad.",
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            "description": "Listado de eventos obtenido exitosamente",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "Listado exitoso",
                            "value": {
                                "items": [
                                    {
                                        "audit_id": "123",
                                        "user": "Juan Pérez",
                                        "origin": "AUTH",
                                        "event_type": "LOGIN",
                                        "result": "SUCCESS",
                                        "created_at": "2024-01-01T10:00:00Z"
                                    }
                                ],
                                "total": 45,
                                "page": 1,
                                "size": 10,
                                "total_pages": 5
                            }
                        }
                    }
                }
            }
        },

        400: {
            "description": "Parámetros de solicitud inválidos",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_params": {
                            "value": {
                                "detail": {
                                    "code": "INVALID_REQUEST",
                                    "meta": {}
                                }
                            }
                        }
                    }
                }
            }
        },

        401: {
            "description": "No autenticado",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_token": {
                            "value": {
                                "detail": {
                                    "code": "AUTH_INVALID_TOKEN",
                                    "meta": {}
                                }
                            }
                        }
                    }
                }
            }
        },

        403: {
            "description": "No autorizado para consultar auditoría",
            "content": {
                "application/json": {
                    "examples": {
                        "no_permission": {
                            "value": {
                                "detail": {
                                    "code": "AUTH_INSUFFICIENT_PERMISSIONS",
                                    "meta": {
                                        "required_permission": "030"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },

        500: {
            "description": "Error interno del servidor"
        }
    }
)
def list_audit_logs(
    request: ListAuditRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """
    Lista los eventos de auditoría del sistema con paginación y filtros avanzados.

    Permite consultar logs de auditoría para análisis de actividad, trazabilidad
    y monitoreo del sistema.

    Args:
        request (ListAuditRequest):
            Parámetros de paginación y filtrado:
            - page_index: Número de página (debe ser >= 1)
            - page_size: Tamaño de página (debe ser >= 1)
            - search: Texto de búsqueda
            - origin: Módulo origen del evento (AUTH, USERS, etc.)
            - result: Resultado del evento (SUCCESS, FAILURE)
            - user_id: ID del usuario asociado
            - event_type: Tipo de evento (LOGIN, CREATE_USER, etc.)
            - start_date: Fecha inicial del filtro
            - end_date: Fecha final del filtro

        db (Session):
            Sesión de base de datos.

        current_user:
            Usuario autenticado con permisos de auditoría ("030").

        current_user_id:
            ID del usuario autenticado.

    Returns:
        PaginatedAuditResponse:
            Objeto con lista paginada de eventos:
            - items: Lista de eventos de auditoría
                - audit_id: ID del evento
                - user: Nombre del usuario
                - origin: Módulo origen
                - event_type: Tipo de evento
                - result: Resultado (SUCCESS/FAILURE)
                - created_at: Fecha del evento
            - total: Número total de registros
            - page: Página actual
            - size: Tamaño de página
            - total_pages: Total de páginas disponibles

    Raises:
        HTTPException 400:
            - PAGE_INDEX_INVALID
            - PAGE_SIZE_INVALID

        HTTPException 401:
            - AUTH_INVALID_TOKEN
            - AUTH_MISSING_TOKEN

        HTTPException 403:
            - AUTH_INSUFFICIENT_PERMISSIONS

        HTTPException 500:
            - INTERNAL_SERVER_ERROR

    Process Flow:
        1. Validación de parámetros de paginación
        2. Construcción de filtros dinámicos
        3. Consulta paginada en base de datos
        4. Transformación de resultados
        5. Retorno de respuesta con metadatos

    Notes:
        - Requiere permiso "030" para acceder
        - Soporta múltiples filtros combinables
        - Optimizado para grandes volúmenes de logs
        - Base para dashboards de auditoría
        - La paginación inicia en 1 (no en 0)
    """
    service = AuditService()

    return service.get_audit_logs(
        db=db,
        page_index=request.page_index,
        page_size=request.page_size,
        search=request.search,
        origin=request.origin,
        result=request.result,
        user_id=request.user_id,
        event_type=request.event_type,
        start_date=request.start_date,
        end_date=request.end_date,
        current_user=current_user
    )

@router.get(
    "/users",
    summary="Listar usuarios para filtros de auditoría",
    description="Obtiene la lista de usuarios disponibles en el sistema para ser utilizados en filtros dentro del módulo de auditoría.",
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            "description": "Listado de usuarios obtenido exitosamente",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "Listado exitoso",
                            "value": [
                                {
                                    "id": "123e4567-e89b-12d3-a456-426614174000",
                                    "name": "Juan Pérez"
                                },
                                {
                                    "id": "223e4567-e89b-12d3-a456-426614174001",
                                    "name": "María Gómez"
                                }
                            ]
                        }
                    }
                }
            }
        },

        401: {
            "description": "Error de autenticación",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_token": {
                            "summary": "Token inválido o expirado",
                            "value": {
                                "detail": {
                                    "code": "AUTH_INVALID_TOKEN",
                                    "meta": {}
                                }
                            }
                        },
                        "missing_token": {
                            "summary": "Token no proporcionado",
                            "value": {
                                "detail": {
                                    "code": "AUTH_MISSING_TOKEN",
                                    "meta": {}
                                }
                            }
                        }
                    }
                }
            }
        },

        403: {
            "description": "Error de autorización",
            "content": {
                "application/json": {
                    "examples": {
                        "insufficient_permissions": {
                            "summary": "Permisos insuficientes",
                            "value": {
                                "detail": {
                                    "code": "AUTH_INSUFFICIENT_PERMISSIONS",
                                    "meta": {
                                        "required_permission": "030"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },

        500: {
            "description": "Error interno del servidor",
            "content": {
                "application/json": {
                    "examples": {
                        "internal_error": {
                            "summary": "Error inesperado",
                            "value": {
                                "detail": {
                                    "code": "INTERNAL_SERVER_ERROR",
                                    "meta": {}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
)
def list_users(
    db: Session = Depends(get_db),
    repository: AuditRepository = Depends(AuditRepository),
    current_user=Depends(get_current_user)
):
    """
    Obtiene una lista básica de usuarios del sistema para uso en filtros de auditoría.

    Este endpoint retorna únicamente información esencial de los usuarios,
    permitiendo su uso en componentes de interfaz como selects o filtros.

    Args:
        db (Session):
            Sesión activa de base de datos.

        repository (AuditRepository):
            Repositorio encargado de acceder a los datos de auditoría.

        current_user:
            Usuario autenticado que realiza la solicitud.
            Debe tener permiso "030" para acceder al módulo de auditoría.

    Returns:
        List[dict]:
            Lista de usuarios con información básica:
            - id: ID único del usuario (UUID en formato string)
            - name: Nombre del usuario

    Raises:
        HTTPException 401:
            - AUTH_INVALID_TOKEN
            - AUTH_MISSING_TOKEN

        HTTPException 403:
            - AUTH_INSUFFICIENT_PERMISSIONS

        HTTPException 500:
            - INTERNAL_SERVER_ERROR

    Process Flow:
        1. Validación de permisos del usuario ("030")
        2. Consulta de usuarios en el repositorio
        3. Transformación de resultados a formato simplificado
        4. Retorno de lista de usuarios

    Notes:
        - No retorna información sensible
        - Diseñado para poblar filtros en el módulo de auditoría
        - No incluye paginación
        - Los IDs son convertidos a string
    """

    service =  PermissionsService()

    if not service.validate_permission(
            db, 
            current_user.get('role'), 
            "030"  # Código del permiso para listar auditoria
    ):
        audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)


    users = repository.list_users(db)

    return [
        {"id": str(user.user_id), "name": user.name}
        for user in users
    ]


@router.get(
    "/origins",
    summary="Listar orígenes (módulos) de auditoría",
    description="Obtiene la lista de módulos/orígenes desde donde se generan los eventos de auditoría para ser utilizados en filtros del sistema.",
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            "description": "Listado de orígenes obtenido exitosamente",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "Listado exitoso",
                            "value": [
                                {"code": "AUTH"},
                                {"code": "USERS"},
                                {"code": "PAYMENTS"},
                                {"code": "ORDERS"}
                            ]
                        }
                    }
                }
            }
        },

        401: {
            "description": "Error de autenticación",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_token": {
                            "summary": "Token inválido o expirado",
                            "value": {
                                "detail": {
                                    "code": "AUTH_INVALID_TOKEN",
                                    "meta": {}
                                }
                            }
                        },
                        "missing_token": {
                            "summary": "Token no proporcionado",
                            "value": {
                                "detail": {
                                    "code": "AUTH_MISSING_TOKEN",
                                    "meta": {}
                                }
                            }
                        }
                    }
                }
            }
        },

        403: {
            "description": "Error de autorización",
            "content": {
                "application/json": {
                    "examples": {
                        "insufficient_permissions": {
                            "summary": "Permisos insuficientes",
                            "value": {
                                "detail": {
                                    "code": "AUTH_INSUFFICIENT_PERMISSIONS",
                                    "meta": {
                                        "required_permission": "030"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },

        500: {
            "description": "Error interno del servidor",
            "content": {
                "application/json": {
                    "examples": {
                        "internal_error": {
                            "summary": "Error inesperado",
                            "value": {
                                "detail": {
                                    "code": "INTERNAL_SERVER_ERROR",
                                    "meta": {}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
)
def list_origins(
    db: Session = Depends(get_db),
    repository: AuditRepository = Depends(AuditRepository),
    current_user=Depends(get_current_user)
):
    """
    Obtiene la lista de orígenes (módulos) de eventos de auditoría.

    Este endpoint retorna los diferentes módulos del sistema que generan
    eventos de auditoría, permitiendo su uso en filtros dentro de la interfaz.

    Args:
        db (Session):
            Sesión activa de base de datos.

        repository (AuditRepository):
            Repositorio encargado de obtener los datos de auditoría.

        current_user:
            Usuario autenticado que realiza la solicitud.
            Debe contar con permiso "030".

    Returns:
        List[dict]:
            Lista de módulos/orígenes:
            - code: Código del módulo (ej: AUTH, USERS, PAYMENTS)

    Raises:
        HTTPException 401:
            - AUTH_INVALID_TOKEN
            - AUTH_MISSING_TOKEN

        HTTPException 403:
            - AUTH_INSUFFICIENT_PERMISSIONS

        HTTPException 500:
            - INTERNAL_SERVER_ERROR

    Process Flow:
        1. Validación de permisos del usuario ("030")
        2. Consulta de orígenes en el repositorio
        3. Transformación de resultados a lista de códigos
        4. Retorno de lista de módulos

    Notes:
        - Se utiliza principalmente para poblar filtros en auditoría
        - No incluye información adicional, solo el código del módulo
        - No requiere paginación
        - Representa los diferentes dominios funcionales del sistema
    """

    service =  PermissionsService()

    if not service.validate_permission(
            db, 
            current_user.get('role'), 
            "030"  # Código del permiso para listar auditoria
    ):
        audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)


    origins = repository.list_origins(db)

    return [{"code": origin.module_code} for origin in origins]


@router.get(
    "/events",
    summary="Listar tipos de eventos de auditoría",
    description="Obtiene la lista de tipos de eventos registrados en el sistema de auditoría para ser utilizados en filtros de la interfaz.",
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            "description": "Listado de eventos obtenido exitosamente",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "Listado exitoso",
                            "value": [
                                {"code": "LOGIN"},
                                {"code": "CREATE_USER"},
                                {"code": "UPDATE_PROFILE"},
                                {"code": "DELETE_USER"}
                            ]
                        }
                    }
                }
            }
        },

        401: {
            "description": "Error de autenticación",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_token": {
                            "summary": "Token inválido o expirado",
                            "value": {
                                "detail": {
                                    "code": "AUTH_INVALID_TOKEN",
                                    "meta": {}
                                }
                            }
                        },
                        "missing_token": {
                            "summary": "Token no proporcionado",
                            "value": {
                                "detail": {
                                    "code": "AUTH_MISSING_TOKEN",
                                    "meta": {}
                                }
                            }
                        }
                    }
                }
            }
        },

        403: {
            "description": "Error de autorización",
            "content": {
                "application/json": {
                    "examples": {
                        "insufficient_permissions": {
                            "summary": "Permisos insuficientes",
                            "value": {
                                "detail": {
                                    "code": "AUTH_INSUFFICIENT_PERMISSIONS",
                                    "meta": {
                                        "required_permission": "030"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },

        500: {
            "description": "Error interno del servidor",
            "content": {
                "application/json": {
                    "examples": {
                        "internal_error": {
                            "summary": "Error inesperado",
                            "value": {
                                "detail": {
                                    "code": "INTERNAL_SERVER_ERROR",
                                    "meta": {}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
)
def list_events(
    db: Session = Depends(get_db),
    repository: AuditRepository = Depends(AuditRepository),
     current_user=Depends(get_current_user)
):
    """
    Obtiene la lista de tipos de eventos de auditoría.

    Este endpoint retorna los códigos de las acciones registradas en el sistema,
    permitiendo su uso en filtros dentro del módulo de auditoría.

    Args:
        db (Session):
            Sesión activa de base de datos.

        repository (AuditRepository):
            Repositorio encargado de acceder a los datos de auditoría.

        current_user:
            Usuario autenticado que realiza la solicitud.
            Debe contar con permiso "030".

    Returns:
        List[dict]:
            Lista de eventos:
            - code: Código del evento (ej: LOGIN, CREATE_USER, UPDATE_PROFILE)

    Raises:
        HTTPException 401:
            - AUTH_INVALID_TOKEN
            - AUTH_MISSING_TOKEN

        HTTPException 403:
            - AUTH_INSUFFICIENT_PERMISSIONS

        HTTPException 500:
            - INTERNAL_SERVER_ERROR

    Process Flow:
        1. Validación de permisos del usuario ("030")
        2. Consulta de eventos en el repositorio
        3. Transformación de resultados a lista de códigos
        4. Retorno de lista de eventos

    Notes:
        - Se utiliza principalmente para poblar filtros en auditoría
        - Representa acciones ejecutadas en el sistema
        - No incluye información adicional, solo el código del evento
        - No requiere paginación
    """

    service =  PermissionsService()

    if not service.validate_permission(
            db, 
            current_user.get('role'), 
            "030"  # Código del permiso para listar auditoria
    ):
        audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)


    events = repository.list_events(db)

    return [{"code": event.action_code, "label": event.label} for event in events]

@router.get(
    "/results",
    summary="Listar resultados de eventos de auditoría",
    description="Obtiene la lista de posibles resultados de los eventos de auditoría para ser utilizados en filtros dentro del sistema.",
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            "description": "Listado de resultados obtenido exitosamente",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "Listado exitoso",
                            "value": [
                                {"code": "SUCCESS"},
                                {"code": "FAILURE"},
                                {"code": "ERROR"}
                            ]
                        }
                    }
                }
            }
        },

        401: {
            "description": "Error de autenticación",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_token": {
                            "summary": "Token inválido o expirado",
                            "value": {
                                "detail": {
                                    "code": "AUTH_INVALID_TOKEN",
                                    "meta": {}
                                }
                            }
                        },
                        "missing_token": {
                            "summary": "Token no proporcionado",
                            "value": {
                                "detail": {
                                    "code": "AUTH_MISSING_TOKEN",
                                    "meta": {}
                                }
                            }
                        }
                    }
                }
            }
        },

        403: {
            "description": "Error de autorización",
            "content": {
                "application/json": {
                    "examples": {
                        "insufficient_permissions": {
                            "summary": "Permisos insuficientes",
                            "value": {
                                "detail": {
                                    "code": "AUTH_INSUFFICIENT_PERMISSIONS",
                                    "meta": {
                                        "required_permission": "030"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },

        500: {
            "description": "Error interno del servidor",
            "content": {
                "application/json": {
                    "examples": {
                        "internal_error": {
                            "summary": "Error inesperado",
                            "value": {
                                "detail": {
                                    "code": "INTERNAL_SERVER_ERROR",
                                    "meta": {}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
)
def list_results(
    db: Session = Depends(get_db),
    repository: AuditRepository = Depends(AuditRepository),
    current_user=Depends(get_current_user)
):
    """
    Obtiene la lista de resultados de eventos de auditoría.

    Este endpoint retorna los posibles estados finales de los eventos registrados,
    permitiendo su uso en filtros dentro del módulo de auditoría.

    Args:
        db (Session):
            Sesión activa de base de datos.

        repository (AuditRepository):
            Repositorio encargado de acceder a los datos de auditoría.

        current_user:
            Usuario autenticado que realiza la solicitud.
            Debe contar con permiso "030".

    Returns:
        List[dict]:
            Lista de resultados:
            - code: Resultado del evento (ej: SUCCESS, FAILURE, ERROR)

    Raises:
        HTTPException 401:
            - AUTH_INVALID_TOKEN
            - AUTH_MISSING_TOKEN

        HTTPException 403:
            - AUTH_INSUFFICIENT_PERMISSIONS

        HTTPException 500:
            - INTERNAL_SERVER_ERROR

    Process Flow:
        1. Validación de permisos del usuario ("030")
        2. Consulta de resultados en el repositorio
        3. Transformación de resultados a lista de códigos
        4. Retorno de lista de resultados

    Notes:
        - Se utiliza principalmente para poblar filtros en auditoría
        - Representa el estado final de los eventos (éxito, fallo, error)
        - No incluye información adicional, solo el código del resultado
        - No requiere paginación
    """

    service =  PermissionsService()

    if not service.validate_permission(
            db, 
            current_user.get('role'), 
            "030"  # Código del permiso para listar auditoria
    ):
        audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)


    results = repository.list_results(db)

    return [{"code": result.outcome} for result in results]


# ==================== ERRORES ====================

@router.post(
    "/errors/list",
    summary="Listar errores de proyectos externos",
    description="Obtiene una lista paginada de errores registrados provenientes de proyectos externos con filtros avanzados para monitoreo y diagnóstico.",
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            "description": "Listado de errores obtenido exitosamente",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "Listado exitoso",
                            "value": {
                                "items": [
                                    {
                                        "error_id": "123e4567-e89b-12d3-a456-426614174000",
                                        "project": "PAYMENTS",
                                        "component": "API",
                                        "error_code": "TIMEOUT",
                                        "severity": "CRITICAL",
                                        "message": "Timeout en servicio externo",
                                        "created_at": "2024-01-01T10:00:00Z"
                                    },
                                    {
                                        "error_id": "223e4567-e89b-12d3-a456-426614174001",
                                        "project": "AUTH",
                                        "component": "SERVICE",
                                        "error_code": "VALIDATION_ERROR",
                                        "severity": "WARNING",
                                        "message": "Error de validación de datos",
                                        "created_at": "2024-01-02T12:30:00Z"
                                    }
                                ],
                                "total": 50,
                                "page": 1,
                                "size": 10,
                                "total_pages": 5
                            }
                        }
                    }
                }
            }
        },

        400: {
            "description": "Error en parámetros de paginación o filtros",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_params": {
                            "summary": "Parámetros inválidos",
                            "value": {
                                "detail": {
                                    "code": "INVALID_REQUEST",
                                    "meta": {}
                                }
                            }
                        },
                        "page_index_invalid": {
                            "summary": "Índice de página inválido",
                            "value": {
                                "detail": {
                                    "code": "PAGE_INDEX_INVALID",
                                    "meta": {
                                        "provided_value": 0,
                                        "min_value": 1
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },

        401: {
            "description": "Error de autenticación",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_token": {
                            "summary": "Token inválido o expirado",
                            "value": {
                                "detail": {
                                    "code": "AUTH_INVALID_TOKEN",
                                    "meta": {}
                                }
                            }
                        },
                        "missing_token": {
                            "summary": "Token no proporcionado",
                            "value": {
                                "detail": {
                                    "code": "AUTH_MISSING_TOKEN",
                                    "meta": {}
                                }
                            }
                        }
                    }
                }
            }
        },

        403: {
            "description": "Error de autorización",
            "content": {
                "application/json": {
                    "examples": {
                        "insufficient_permissions": {
                            "summary": "Permisos insuficientes",
                            "value": {
                                "detail": {
                                    "code": "AUTH_INSUFFICIENT_PERMISSIONS",
                                    "meta": {
                                        "required_permission": "031"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },

        500: {
            "description": "Error interno del servidor",
            "content": {
                "application/json": {
                    "examples": {
                        "internal_error": {
                            "summary": "Error inesperado",
                            "value": {
                                "detail": {
                                    "code": "INTERNAL_SERVER_ERROR",
                                    "meta": {}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
)
def list_errors_EP(
    request: ListErrorsRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """
    Lista los errores provenientes de proyectos externos con paginación y filtros avanzados.

    Permite consultar logs de errores para monitoreo, diagnóstico y trazabilidad
    en integraciones o procesos del sistema.

    Args:
        request (ListErrorsRequest):
            Parámetros de paginación y filtrado:
            - page_index: Número de página (>= 1)
            - page_size: Tamaño de página (>= 1)
            - search: Texto de búsqueda
            - severity: Nivel de severidad (CRITICAL, WARNING, INFO)
            - project: Proyecto origen del error
            - component: Componente donde ocurrió el error
            - error_code: Código técnico del error
            - start_date: Fecha inicial del filtro
            - end_date: Fecha final del filtro

        db (Session):
            Sesión activa de base de datos.

        current_user:
            Usuario autenticado con permiso "031".

        current_user_id:
            ID del usuario autenticado.

    Returns:
        dict:
            Objeto con lista paginada de errores:
            - items: Lista de errores
            - total: Número total de registros
            - page: Página actual
            - size: Tamaño de página
            - total_pages: Total de páginas disponibles

    Raises:
        HTTPException 400:
            - INVALID_REQUEST
            - PAGE_INDEX_INVALID
            - PAGE_SIZE_INVALID

        HTTPException 401:
            - AUTH_INVALID_TOKEN
            - AUTH_MISSING_TOKEN

        HTTPException 403:
            - AUTH_INSUFFICIENT_PERMISSIONS

        HTTPException 500:
            - INTERNAL_SERVER_ERROR

    Process Flow:
        1. Validación de parámetros de paginación
        2. Construcción de filtros dinámicos
        3. Consulta paginada en base de datos
        4. Transformación de resultados
        5. Retorno de respuesta con metadatos

    Notes:
        - Requiere permiso "031"
        - Diseñado para monitoreo de errores en integraciones externas
        - Soporta múltiples filtros combinables
        - Optimizado para grandes volúmenes de logs
        - La paginación inicia en 1
    """

    perm_service =  PermissionsService()

    if not perm_service.validate_permission(
            db, 
            current_user.get('role'), 
            "031"  # Código del permiso para listar  auditoria de errores en PE
    ):
        audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)


    service = AuditService()

    return service.get_errors_EP(
        db=db,
        page_index=request.page_index,
        page_size=request.page_size,
        search=request.search,
        severity=request.severity,
        project=request.project,
        component=request.component,
        error_code=request.error_code,
        start_date=request.start_date,
        end_date=request.end_date
    )

@router.get(
    "/errors/components",
    summary="Listar componentes de errores",
    description="Obtiene la lista de componentes donde se han generado errores en proyectos externos para ser utilizados en filtros del sistema.",
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            "description": "Listado de componentes obtenido exitosamente",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "Listado exitoso",
                            "value": [
                                {"code": "API"},
                                {"code": "BACKEND"},
                                {"code": "FRONTEND"},
                                {"code": "DATABASE"}
                            ]
                        }
                    }
                }
            }
        },

        401: {
            "description": "Error de autenticación",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_token": {
                            "summary": "Token inválido o expirado",
                            "value": {
                                "detail": {
                                    "code": "AUTH_INVALID_TOKEN",
                                    "meta": {}
                                }
                            }
                        },
                        "missing_token": {
                            "summary": "Token no proporcionado",
                            "value": {
                                "detail": {
                                    "code": "AUTH_MISSING_TOKEN",
                                    "meta": {}
                                }
                            }
                        }
                    }
                }
            }
        },

        403: {
            "description": "Error de autorización",
            "content": {
                "application/json": {
                    "examples": {
                        "insufficient_permissions": {
                            "summary": "Permisos insuficientes",
                            "value": {
                                "detail": {
                                    "code": "AUTH_INSUFFICIENT_PERMISSIONS",
                                    "meta": {
                                        "required_permission": "031"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },

        500: {
            "description": "Error interno del servidor",
            "content": {
                "application/json": {
                    "examples": {
                        "internal_error": {
                            "summary": "Error inesperado",
                            "value": {
                                "detail": {
                                    "code": "INTERNAL_SERVER_ERROR",
                                    "meta": {}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
)
def list_error_components(
    db: Session = Depends(get_db),
    service: AuditService = Depends(AuditService),
    current_user=Depends(get_current_user)
):
    """
    Obtiene la lista de componentes donde se han generado errores en proyectos externos.

    Este endpoint retorna los diferentes componentes técnicos del sistema
    donde se originan los errores, permitiendo su uso en filtros dentro
    del módulo de monitoreo de errores.

    Args:
        db (Session):
            Sesión activa de base de datos.

        service (AuditService):
            Servicio encargado de la lógica de auditoría y errores.

        current_user:
            Usuario autenticado que realiza la solicitud.
            Debe contar con permiso "031".

    Returns:
        List[dict]:
            Lista de componentes:
            - code: Nombre del componente (ej: API, BACKEND, FRONTEND)

    Raises:
        HTTPException 401:
            - AUTH_INVALID_TOKEN
            - AUTH_MISSING_TOKEN

        HTTPException 403:
            - AUTH_INSUFFICIENT_PERMISSIONS

        HTTPException 500:
            - INTERNAL_SERVER_ERROR

    Process Flow:
        1. Validación de permisos del usuario ("031")
        2. Consulta de componentes en el servicio
        3. Filtrado de valores nulos o vacíos
        4. Transformación a lista de códigos
        5. Retorno de resultados

    Notes:
        - Se utiliza principalmente para poblar filtros en la interfaz de errores
        - Representa el origen técnico del error (API, backend, frontend, etc.)
        - Excluye valores nulos o vacíos
        - No requiere paginación
    """
    perm_service =  PermissionsService()

    if not perm_service.validate_permission(
            db, 
            current_user.get('role'), 
            "031"  # Código del permiso para  listar  auditoria de errores en PE
    ):
        audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)


    components = service.get_error_components(db)

    return [
        {"code": component.component}
        for component in components
        if component.component
    ]

@router.get(
    "/errors/codes",
    summary="Listar códigos de error",
    description="Obtiene la lista de códigos de error registrados en proyectos externos para ser utilizados en filtros dentro del sistema.",
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            "description": "Listado de códigos de error obtenido exitosamente",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "Listado exitoso",
                            "value": [
                                {"code": "NETWORK_ERROR"},
                                {"code": "TIMEOUT"},
                                {"code": "VALIDATION_ERROR"},
                                {"code": "AUTH_ERROR"}
                            ]
                        }
                    }
                }
            }
        },

        401: {
            "description": "Error de autenticación",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_token": {
                            "summary": "Token inválido o expirado",
                            "value": {
                                "detail": {
                                    "code": "AUTH_INVALID_TOKEN",
                                    "meta": {}
                                }
                            }
                        },
                        "missing_token": {
                            "summary": "Token no proporcionado",
                            "value": {
                                "detail": {
                                    "code": "AUTH_MISSING_TOKEN",
                                    "meta": {}
                                }
                            }
                        }
                    }
                }
            }
        },

        403: {
            "description": "Error de autorización",
            "content": {
                "application/json": {
                    "examples": {
                        "insufficient_permissions": {
                            "summary": "Permisos insuficientes",
                            "value": {
                                "detail": {
                                    "code": "AUTH_INSUFFICIENT_PERMISSIONS",
                                    "meta": {
                                        "required_permission": "031"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },

        500: {
            "description": "Error interno del servidor",
            "content": {
                "application/json": {
                    "examples": {
                        "internal_error": {
                            "summary": "Error inesperado",
                            "value": {
                                "detail": {
                                    "code": "INTERNAL_SERVER_ERROR",
                                    "meta": {}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
)
def list_error_codes(
    db: Session = Depends(get_db),
    service: AuditService = Depends(AuditService),
     current_user=Depends(get_current_user)
):
    """
    Obtiene la lista de códigos de error registrados en proyectos externos.

    Este endpoint retorna los identificadores técnicos de los errores,
    permitiendo su uso en filtros dentro del módulo de monitoreo.

    Args:
        db (Session):
            Sesión activa de base de datos.

        service (AuditService):
            Servicio encargado de la lógica de auditoría y errores.

        current_user:
            Usuario autenticado que realiza la solicitud.
            Debe contar con permiso "031".

    Returns:
        List[dict]:
            Lista de códigos de error:
            - code: Código técnico del error (ej: NETWORK_ERROR, TIMEOUT)

    Raises:
        HTTPException 401:
            - AUTH_INVALID_TOKEN
            - AUTH_MISSING_TOKEN

        HTTPException 403:
            - AUTH_INSUFFICIENT_PERMISSIONS

        HTTPException 500:
            - INTERNAL_SERVER_ERROR

    Process Flow:
        1. Validación de permisos del usuario ("031")
        2. Consulta de códigos de error en el servicio
        3. Filtrado de valores nulos o vacíos
        4. Transformación a lista de códigos
        5. Retorno de resultados

    Notes:
        - Se utiliza principalmente para poblar filtros en la interfaz de errores
        - Representa identificadores técnicos de fallos
        - Excluye valores nulos o vacíos
        - No requiere paginación
    """

    perm_service =  PermissionsService()

    if not perm_service.validate_permission(
            db, 
            current_user.get('role'), 
            "031"  # Código del permiso para  listar  auditoria de errores en PE
    ):
        audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)

    codes = service.get_error_codes(db)

    return [
        {"code": code.error_code}
        for code in codes
        if code.error_code
    ]


@router.get(
    "/errors/severity",
    summary="Listar niveles de severidad de errores",
    description="Obtiene la lista de niveles de severidad registrados en errores de proyectos externos para ser utilizados en filtros del sistema.",
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            "description": "Listado de severidades obtenido exitosamente",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "Listado exitoso",
                            "value": [
                                {"code": "CRITICAL"},
                                {"code": "WARNING"},
                                {"code": "INFO"}
                            ]
                        }
                    }
                }
            }
        },

        401: {
            "description": "Error de autenticación",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_token": {
                            "summary": "Token inválido o expirado",
                            "value": {
                                "detail": {
                                    "code": "AUTH_INVALID_TOKEN",
                                    "meta": {}
                                }
                            }
                        },
                        "missing_token": {
                            "summary": "Token no proporcionado",
                            "value": {
                                "detail": {
                                    "code": "AUTH_MISSING_TOKEN",
                                    "meta": {}
                                }
                            }
                        }
                    }
                }
            }
        },

        403: {
            "description": "Error de autorización",
            "content": {
                "application/json": {
                    "examples": {
                        "insufficient_permissions": {
                            "summary": "Permisos insuficientes",
                            "value": {
                                "detail": {
                                    "code": "AUTH_INSUFFICIENT_PERMISSIONS",
                                    "meta": {
                                        "required_permission": "031"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },

        500: {
            "description": "Error interno del servidor",
            "content": {
                "application/json": {
                    "examples": {
                        "internal_error": {
                            "summary": "Error inesperado",
                            "value": {
                                "detail": {
                                    "code": "INTERNAL_SERVER_ERROR",
                                    "meta": {}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
)
def list_error_severity(
    db: Session = Depends(get_db),
    service: AuditService = Depends(AuditService),
     current_user=Depends(get_current_user)
):
    """
    Obtiene la lista de niveles de severidad de errores registrados en proyectos externos.

    Este endpoint retorna los niveles de impacto o criticidad de los errores,
    permitiendo su uso en filtros dentro del módulo de monitoreo.

    Args:
        db (Session):
            Sesión activa de base de datos.

        service (AuditService):
            Servicio encargado de la lógica de auditoría y errores.

        current_user:
            Usuario autenticado que realiza la solicitud.
            Debe contar con permiso "031".

    Returns:
        List[dict]:
            Lista de niveles de severidad:
            - code: Nivel de severidad (ej: CRITICAL, WARNING, INFO)

    Raises:
        HTTPException 401:
            - AUTH_INVALID_TOKEN
            - AUTH_MISSING_TOKEN

        HTTPException 403:
            - AUTH_INSUFFICIENT_PERMISSIONS

        HTTPException 500:
            - INTERNAL_SERVER_ERROR

    Process Flow:
        1. Validación de permisos del usuario ("031")
        2. Consulta de severidades en el servicio
        3. Filtrado de valores nulos o vacíos
        4. Transformación a lista de códigos
        5. Retorno de resultados

    Notes:
        - Se utiliza principalmente para poblar filtros en la interfaz de errores
        - Representa el nivel de impacto o criticidad del error
        - Excluye valores nulos o vacíos
        - No requiere paginación
    """

    perm_service =  PermissionsService()

    if not perm_service.validate_permission(
            db, 
            current_user.get('role'), 
            "031"  # Código del permiso PARA  listar  auditoria de errores en PE
    ):
        audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)

    severities = service.get_error_severity(db)

    return [
        {"code": severity.severity}
        for severity in severities
        if severity.severity
    ]


# ==================== EXPORTACIÓN ASÍNCRONA (RF-INT-08) ====================


def _require_audit_export_permission(db: Session, current_user: dict) -> None:
    if not PermissionsService().validate_permission(
        db,
        current_user.get("role"),
        settings.audit_export_permission_code,
    ):
        audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)


@router.post(
    "/exports",
    response_model=AuditExportJobResponse,
    summary="Solicitar exportación asíncrona de auditoría",
)
def create_audit_export(
    body: CreateAuditExportRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    _require_audit_export_permission(db, current_user)
    return create_audit_export_job(db, request=request, current_user=current_user, body=body)


@router.get(
    "/exports",
    response_model=List[AuditExportJobResponse],
    summary="Listar exportaciones del usuario",
)
def list_audit_exports(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    limit: int = Query(50, ge=1, le=200),
):
    _require_audit_export_permission(db, current_user)
    uid = current_user["user"].user_id
    jobs = list_jobs_for_user(uid, limit=limit)
    return [job_to_response(j) for j in jobs]


@router.get(
    "/exports/{export_id}",
    response_model=AuditExportJobResponse,
    summary="Estado de una exportación",
)
def get_audit_export(
    export_id: UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    _require_audit_export_permission(db, current_user)
    uid = current_user["user"].user_id
    job = get_job_for_user(export_id, uid)
    if not job:
        audit_error("EXPORT_NOT_FOUND", status.HTTP_404_NOT_FOUND)
    inc = job.get("status") == "COMPLETED"
    return job_to_response(job, include_download=inc)


@router.get(
    "/exports/{export_id}/download",
    summary="Descargar archivo de exportación (token temporal)",
)
def download_audit_export(
    export_id: UUID,
    token: str = Query(..., description="JWT de descarga"),
    db: Session = Depends(get_db),
):
    try:
        payload = decode_export_download_token(token)
    except JWTError:
        audit_error("AUTH_INVALID_TOKEN", status.HTTP_401_UNAUTHORIZED)
    if payload.get("eid") != str(export_id):
        audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)

    job = job_store.load(export_id)
    if not job or job.get("request_by") != payload.get("sub"):
        audit_error("AUTH_INSUFFICIENT_PERMISSIONS", status.HTTP_403_FORBIDDEN)
    if job.get("status") != "COMPLETED":
        audit_error("EXPORT_NOT_READY", status.HTTP_400_BAD_REQUEST)

    fp = job.get("file_path")
    if not fp:
        audit_error("EXPORT_FILE_MISSING", status.HTTP_404_NOT_FOUND)
    path = Path(fp)
    if not path.is_file():
        audit_error("EXPORT_FILE_MISSING", status.HTTP_404_NOT_FOUND)

    repo = AuditRepository()
    try:
        ag = repo.get_project_by_code(db, code="AGROFUSION")
        pid = ag.af_project_id if ag else None
        repo.log_event_optional_term(
            db,
            action_code="EXPORT_DOWNLOADED",
            outcome="success",
            module_code="AUDIT_EXPORT",
            project_id=pid,
            actor_id=UUID(payload["sub"]),
            metadata={"export_request_id": str(export_id), "file_hash": job.get("file_hash")},
        )
    except Exception:
        pass

    media = {
        "CSV": "text/csv; charset=utf-8",
        "JSONL": "application/x-ndjson; charset=utf-8",
        "XLSX": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "PDF": "application/pdf",
    }.get(job.get("format", ""), "application/octet-stream")

    fname = job.get("download_filename") or (
        f"AgroFusion_Auditoria_{export_id}.{str(path.suffix).lstrip('.')}"
    )
    return FileResponse(
        path=str(path),
        filename=fname,
        media_type=media,
    )


@router.delete(
    "/exports/{export_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Eliminar exportación y archivo asociado",
)
def delete_audit_export(
    export_id: UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    _require_audit_export_permission(db, current_user)
    uid = current_user["user"].user_id
    job = get_job_for_user(export_id, uid)
    if not job:
        audit_error("EXPORT_NOT_FOUND", status.HTTP_404_NOT_FOUND)

    fp = job.get("file_path")
    if fp:
        p = Path(fp)
        if p.is_file():
            try:
                p.unlink()
            except OSError:
                pass

    job_store.delete_job_file(export_id)

    repo = AuditRepository()
    try:
        ag = repo.get_project_by_code(db, code="AGROFUSION")
        pid = ag.af_project_id if ag else None
        repo.log_event_optional_term(
            db,
            action_code="EXPORT_DELETED",
            outcome="success",
            module_code="AUDIT_EXPORT",
            project_id=pid,
            actor_id=uid,
            metadata={"export_request_id": str(export_id)},
        )
    except Exception:
        pass

    return Response(status_code=status.HTTP_204_NO_CONTENT)