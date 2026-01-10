from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session      
from app.core.database import get_db

router = APIRouter(prefix="/audit", tags=["Auditory"])



@router.post("/login")
def login(request: Request, db: Session = Depends(get_db)):
    pass;