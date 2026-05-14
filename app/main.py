from fastapi import FastAPI
from app.routes.auth import router as auth_router
from app.middleware.responseHeaders import SecurityHeadersMiddleware

app = FastAPI()

# Middleware get's added here
app.add_middleware(SecurityHeadersMiddleware)

app.include_router(auth_router)
