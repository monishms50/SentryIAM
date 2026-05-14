import uuid
from datetime import datetime, timedelta, timezone
from app.config import settings
import secrets
import hashlib
from jose import jwt, JWTError, ExpiredSignatureError
from fastapi import HTTPException


def create_access_token(user_id: str, role: str) -> str:
    #  Getting current time and adding a delta specified in the config file. This will generate the life-time/expiration for the token.
    expiration_time = int((datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp())

    payload = {
        "sub": str(user_id),
        "role": role,
        "exp": expiration_time,
        "jti": str(uuid.uuid4())
    }
    #  Return the JWT token with the alogrithm as per the config file

    return jwt.encode(payload, settings.SECRET_KEY, algorithm = settings.ALGORITHM)



def create_refresh_token() -> tuple:
    #   Create a refresh token
    refresh_token = secrets.token_urlsafe(32)

    #    Hash it
    hashed_ref_token = hashlib.sha256(refresh_token.encode()).hexdigest()

    return (refresh_token,hashed_ref_token)



def decode_access_token(raw_token: str) -> dict:

    # Return the payload if valid
    try:
        return jwt.decode(raw_token, settings.SECRET_KEY, algorithms = [settings.ALGORITHM])
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
