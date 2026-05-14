from sqlalchemy.orm import Session
from app.models.refresh_token import RefreshToken
from app.utils.jwt import create_access_token, create_refresh_token
from datetime import datetime, timedelta, timezone
from app.config import settings

def issue_token_pair(user_id, db: Session):
    # Generate JWT access token
    access_token = create_access_token(user_id, role="user")
    
    # Generate refresh token
    refresh_token, refresh_token_hash = create_refresh_token()
    
    # Store refresh token hash in DB
    refresh_token_entry = RefreshToken(
        user_id=user_id,
        token_hash=refresh_token_hash,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )
    db.add(refresh_token_entry)
    db.commit()
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token
    }
