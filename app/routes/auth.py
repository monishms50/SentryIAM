from fastapi import APIRouter, HTTPException, Depends, Request
from sqlalchemy.orm import Session
from app.database import get_db
from app.schemas.register import RegisterRequest
from app.schemas.login import LoginRequest
from app.schemas.refresh import RefreshRequest
from app.models.user import User
from app.models.refresh_token import RefreshToken 
from app.models.audit_log import AuditLog
from app.utils.jwt import create_access_token, create_refresh_token
from app.utils.tokens import issue_token_pair
from app.utils.audit import log_event
from datetime import datetime, timedelta, timezone
from app.config import settings
from app.dependencies.auth import get_current_user

import hashlib
import bcrypt



router = APIRouter()

@router.post("/auth/register", status_code=201)
def register(request: Request, body: RegisterRequest, db: Session = Depends(get_db)):

    # Check for duplicate email
    existing_user = db.query(User).filter(User.email == body.email).first()
    if existing_user:
        # Log fsilure
        event_type="REGISTER_FAILED"       
        log_event(db, event_type, success= False, user_id = None, request= request)
        raise HTTPException(status_code=409, detail="Email already exists")

    # Hash the password
    hashed_password = bcrypt.hashpw(
        body.password.encode("utf-8"),
        bcrypt.gensalt(rounds=12)
    )

    # Create and save new user
    new_user = User(
        email=body.email,
        hashed_password=hashed_password.decode("utf-8")
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Log success
    log_event(db, "REGISTER_SUCCESS", success=True, user_id=new_user.id, request=request)
    return {"message": "User registered successfully", "user_id": str(new_user.id)}
    

@router.post("/auth/login", status_code=200)
def login(request: Request, body: LoginRequest, db: Session = Depends(get_db)):

    # Fetch user by email from database
    existing_user = db.query(User).filter(User.email == body.email).first()

    # Reject login if user does not exist
    if not existing_user:
        log_event(db, "LOGIN_FAILED", success=False, user_id=None, request=request)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Verify password using bcrypt hash comparison
    password_match = bcrypt.checkpw(
        body.password.encode("utf-8"),
        existing_user.hashed_password.encode("utf-8")
    )

    # Reject login if password is incorrect
    if not password_match:
        log_event(db, "LOGIN_FAILED", success=False, user_id=existing_user.id, request=request)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Return token pair to client
    log_event(db, "LOGIN_SUCCESS", success=True, user_id=existing_user.id, request=request)
    return issue_token_pair(existing_user.id, db)



@router.post("/auth/refresh", status_code=200)
def refresh( request: Request, body : RefreshRequest, db: Session = Depends(get_db)):
    # Hash the incoming raw token
    hashed_refresh_token = hashlib.sha256(body.refresh_token.encode()).hexdigest()

    # Look up token in DB
    token_entry = db.query(RefreshToken).filter(RefreshToken.token_hash == hashed_refresh_token).first()

    # Token not found
    if not token_entry:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    # Reuse detection: The user can have multiple devices or sessions. So then could be many tokens for the same user. If one of the token was token was already revoked and an attempt was made with this token, then we know this could be suspecious activity, so we revoke all token for this user. 
    if token_entry.revoked:
        # Revoke ALL tokens for this user
        db.query(RefreshToken).filter(RefreshToken.user_id == token_entry.user_id).update({"revoked": True})
        
        # Log Token abuse detection
        log_event(db, event_type="TOKEN_REUSE_DETECTED", success= False, user_id=token_entry.user_id, request= request)
        raise HTTPException(status_code=401, detail="Token reuse detected. Please login again.")

    # Token expired
    if token_entry.expires_at <= datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Refresh token expired")   
        
    # Valid Refresh token. Revoke the token first
    user_id = token_entry.user_id
    token_entry.revoked = True
    db.commit()

    # Return new token pairi
    log_event(db, "TOKEN_REFRESHED", success=True, user_id=user_id, request=request)
    return issue_token_pair(user_id, db)



@router.get("/me", status_code=200)
def me(user = Depends(get_current_user)):
    return {
        "id": user.id, 
        "email": user.email,
        "role": user.role
        }
