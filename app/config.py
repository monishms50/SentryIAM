from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    #  DB URL fields
    DATABASE_URL: str

    #  JWT Config fields
    SECRET_KEY: str
    ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    REFRESH_TOKEN_EXPIRE_DAYS: int

    class Config:
        #  Location of the fild containing all secrets. Must use a KMS
        env_file = ".env"

settings = Settings()
