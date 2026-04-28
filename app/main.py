"""
Punto de entrada principal de la aplicación FastAPI.

Inicializa la aplicación, configura middlewares globales
y registra los routers de la API.
"""

from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.database import SessionLocal
from app.repositories.audit_repository import AuditRepository
from app.routes.audit import router as router_audit
from app.routes.kms import router as router_kms
from app.services.audit_export_worker import (
    start_audit_export_worker,
    stop_audit_export_worker,
)
from app.services.kms_ca_service import KmsCaService


def _seed_root_ca_if_needed() -> None:
    """
    Crea la Root CA interna durante el arranque si no existe una activa.

    Implementa el proceso de seed/inicialización de RF-INT-11 y registra el
    evento ``KMS_CA_CREATED`` en auditoría. El fallo de este paso nunca
    debe impedir el arranque de la aplicación: se reporta a stdout para que
    lo recoja el sistema de logging.
    """
    if not settings.kms_ca_root_autoseed:
        return

    db = SessionLocal()
    try:
        service = KmsCaService()
        existing = service.get_active_ca(db)
        if existing is not None:
            return

        ca = service.initialize_root_ca(
            db=db,
            algorithm=settings.kms_ca_root_algorithm,
            subject=settings.kms_ca_root_subject,
            validity_days=settings.kms_ca_root_validity_days,
            created_by=None,  # Proceso automático del sistema (SYSTEM)
        )

        try:
            project = AuditRepository().get_project_by_code(db, code="AGROFUSION")
            if project is not None:
                AuditRepository().log_event_optional_term(
                    db=db,
                    action_code="KMS_CA_CREATED",
                    outcome="success",
                    module_code="KMS",
                    project_id=project.af_project_id,
                    actor_id=None,
                    metadata={
                        "ca_id": str(ca.ca_id),
                        "subject": ca.subject,
                        "serial_number": ca.serial_number,
                        "fingerprint": ca.fingerprint,
                        "seed": True,
                    },
                )
        except Exception as audit_exc:  # noqa: BLE001
            print(f"[KMS_CA_AUDIT_WARN] No se pudo registrar KMS_CA_CREATED: {audit_exc}")

        print(
            f"[KMS_CA_SEED] Root CA creada durante el arranque "
            f"(ca_id={ca.ca_id}, serial={ca.serial_number})."
        )
    except Exception as e:  # noqa: BLE001
        print(f"[KMS_CA_SEED_WARN] No se pudo inicializar la Root CA: {e}")
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    start_audit_export_worker()
    _seed_root_ca_if_needed()
    yield
    stop_audit_export_worker()


app = FastAPI(
    root_path="/agrofusion/test/audit",
    title="API Inmero - Backend Auditory Agrofusion - Testing",
    version="1.0.0",
    description="API de auditoría para el backend de Agrofusion, encargada del registro y consulta de eventos y errores.",
    lifespan=lifespan,
)
# Orígenes permitidos para solicitudes CORS (frontend)
origins = [
    "https://inmero.co/agrofusionTest",
    "https://www.inmero.co/agrofusionTest",
    "https://inmero.co",
    "https://www.inmero.co"
    "http://localhost:5173",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
]
# Middleware CORS para permitir comunicación entre frontend y backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Registro de rutas relacionadas con auditoría
app.include_router(router_audit)
@app.get("/health")
async def health_check():
    return {"status": "ok"}

# Registro de rutas relacionadas con KMS (Key Management Service)
app.include_router(router_kms)

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=9000,
        reload=True
    )
