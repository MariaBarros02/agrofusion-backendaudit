import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from app.main import app
from app.core.database import get_db
from app.core.config import settings  # donde esté tu DATABASE_URL


# ---------------------------------------------------------
# Engine REAL (misma DB de desarrollo)
# ---------------------------------------------------------
engine = create_engine(
    settings.database_url,
    pool_pre_ping=True
)

TestingSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)


# ---------------------------------------------------------
# Fixture de base de datos con ROLLBACK
# ---------------------------------------------------------
@pytest.fixture(scope="function")
def db():
    """
    Usa la base de datos REAL de desarrollo,
    pero encapsula cada test en una transacción
    que se revierte al finalizar.
    """
    connection = engine.connect()
    transaction = connection.begin()

    session = TestingSessionLocal(bind=connection)

    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


# ---------------------------------------------------------
# Override de dependencia get_db
# ---------------------------------------------------------
def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


# ---------------------------------------------------------
# Cliente FastAPI
# ---------------------------------------------------------
@pytest.fixture(scope="function")
def client():
    """
    Cliente de pruebas para endpoints FastAPI.
    """
    return TestClient(app)
