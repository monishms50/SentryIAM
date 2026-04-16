from pydantic import BaseModel, EmailStr 

class (BaseModel):
    email: EmailStr
    password: str

