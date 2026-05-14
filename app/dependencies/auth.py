from app.utils.jwt import decode_access_token
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.user import User
from fastapi import Depends, HTTPException, Request


def get_current_user(request: Request, db: Session = Depends(get_db)):
    # Extract Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    
    # Strip "Bearer " prefix to get raw token
    token = auth_header.split(" ")[1]
    
    # Decode and verify JWT
    payload = decode_access_token(token)
    
    # Extract user ID from payload
    user_id = payload.get("sub")
    
    # Look up user in DB
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    
    return user
