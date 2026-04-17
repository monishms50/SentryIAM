from fastapi import APIRouter, HTTPException, Depends, Request
from sqlalchemy.orm import Session
from app.database import get_db
from app.schemas.register import RegisterRequest
from app.schemas.login import LoginRequest
from app.models.user import User
from app.models.refresh_token import RefreshToken 
from app.models.audit_log import AuditLog
from app.utils.jwt import create_access_token, create_refresh_token
from datetime import datetime, timedelta, timezone
from app.config import settings

import bcrypt



router = APIRouter()

@router.post("/auth/register", status_code=201)
def register(request: Request, body: RegisterRequest, db: Session = Depends(get_db)):
    ip = request.client.host
    user_agent = request.headers.get("user-agent")

    # Check for duplicate email
    existing_user = db.query(User).filter(User.email == body.email).first()
    if existing_user:
        # Log fsilure
        db.add(AuditLog(
            user_id=None,
            event_type="REGISTER_FAILED",
            ip_address=ip,
            user_agent=user_agent,
            success=False
        ))
        db.commit()
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
    db.add(AuditLog(
        user_id=new_user.id,
        event_type="REGISTER_SUCCESS",
        ip_address=ip,
        user_agent=user_agent,
        success=True
    ))
    db.commit()

    return {"message": "User registered successfully", "user_id": str(new_user.id)}
    
@router.post("/auth/login", status_code=200)
def login(body: LoginRequest, db: Session = Depends(get_db)):

    # Fetch user by email from database
    existing_user = db.query(User).filter(User.email == body.email).first()

    # Reject login if user does not exist
    if not existing_user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Verify password using bcrypt hash comparison
    password_match = bcrypt.checkpw(
        body.password.encode("utf-8"),
        existing_user.hashed_password.encode("utf-8")
    )

    # Reject login if password is incorrect
    if not password_match:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Generate JWT access token for authenticated user
    JWT_token = create_access_token(existing_user.id, role="User")

    # Generate refresh token for session renewal
    refresh_token, refresh_token_hash = create_refresh_token()

    # Create a refresh_token ORM object
    refresh_token_entry = RefreshToken(
        user_id = existing_user.id,
        token_hash = refresh_token_hash,
        expires_at = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        )


    # Store refresh token in DB for session tracking
    db.add(refresh_token_entry)
    db.commit()
        
    # (useful for logout / token revocation)

    # Return authentication tokens to client
    return {
        "access_token": JWT_token,
        "refresh_token": refresh_token
    }
