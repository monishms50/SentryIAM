from fastapi import APIRouter, HTTPException, Depends, Request
from sqlalchemy.orm import Session
from app.database import get_db
from app.schemas.register import RegisterRequest
from app.achema.login import LoginRequest
from app.models.user import User
from app.models.audit_log import AuditLog
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

    #  Check if user exists
    existing_user = db.query(User).filter(User.email == body.email).first()

    #  Check if the account is locked


    if not existing_user:
        #  Throw an error saying the user doesn't exist    
        raise HTTPException(status_code=401, detail="Invalid credentials")

    #  Check if the password matches
    password_match = bcrypt.checkpw(body.password.encode("utf-8"), existing_user.hashed_password) 

    #  Throw an error if the password doesn't match (Gentic error message: Invalid credentials)
    if not password_match:
        raise HTTPException(status_code=409, detail="Invalid credentials")

    #  Create a JWT and Refersh Token for the user if auth is successful


    #  Store the Refresh_token to the DB and log the event 

    #  Send the user a HTTP Reposnse with the JWT




