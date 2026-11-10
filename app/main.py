from fastapi import FastAPI

from app.config import get_settings
from app.email_verifications.router import router as verification_router
from app.password_resets.router import router as reset_router
from app.registrations.router import router as registration_router
from app.sign_in.router import router as sign_in_router
from app.sessions.router import router as sessions_router
from app.social_auth import router as social_auth_router

settings = get_settings()
app = FastAPI(
    title='Authentication API',
    version='1.0.0',
    description='Authentication API with local SQLite development and PostgreSQL production support.',
)
app.include_router(registration_router, prefix='/v1/auth', tags=['registrations'])
app.include_router(verification_router, prefix='/v1/auth', tags=['email verification'])
app.include_router(sign_in_router, prefix='/v1/auth', tags=['sign-in'])
app.include_router(sessions_router, prefix='/v1/auth', tags=['sessions'])
app.include_router(reset_router, prefix='/v1/auth', tags=['password resets'])
app.include_router(social_auth_router, prefix='/v1/auth', tags=['social authentication'])


@app.get('/runtime-config', include_in_schema=False)
def runtime_config():
    return settings.public_runtime_config()


@app.get('/health', include_in_schema=False)
def health():
    return {'status': 'ok'}


if __name__ == '__main__':
    import uvicorn

    uvicorn.run(
        'app.main:app',
        host=settings.server_host,
        port=settings.server_port,
        reload=settings.server_reload,
    )
