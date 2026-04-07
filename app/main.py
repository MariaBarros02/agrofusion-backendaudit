"""
Punto de entrada principal de la aplicación FastAPI.

Inicializa la aplicación, configura middlewares globales
y registra los routers de la API.
"""

from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes.audit import router as router_audit
from app.routes.kms import router as router_kms
from app.services.audit_export_worker import (
    start_audit_export_worker,
    stop_audit_export_worker,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    start_audit_export_worker()
    yield
    stop_audit_export_worker()


app = FastAPI(
    root_path="/agrofusion/audit",
    title="API Inmero - Backend Auditory Agrofusion",
    version="1.0.0",
    description="API de auditoría para el backend de Agrofusion, encargada del registro y consulta de eventos y errores.",
    lifespan=lifespan,
)
# Orígenes permitidos para solicitudes CORS (frontend)
origins = [
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

# Registro de rutas relacionadas con KMS (Key Management Service)
app.include_router(router_kms)

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=9000,
        reload=True
    )
