from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import AccountStatus, AuthProvider, AuthSession, User, get_db
from app.rate_limiting.service import enforce_limit
from app.security import (
    client_ip,
    digest_secret,
    hash_password,
    normalize_email,
    now_utc,
    password_hash_needs_rehash,
    random_token,
    verify_password,
)
from app.social_auth import verify_provider_id_token

router = APIRouter()


class SignInIn(BaseModel):
    email: EmailStr | None = None
    password: str | None = None
    provider: str = 'email'
    id_token: str | None = Field(default=None, min_length=1, max_length=8192)
    nonce: str | None = Field(default=None, min_length=1, max_length=200)

    def normalized_provider(self) -> AuthProvider:
        value = (self.provider or 'email').strip().lower()
        if value in {'google', 'gmail'}:
            return AuthProvider.GOOGLE
        if value in {'apple', 'ios'}:
            return AuthProvider.APPLE
        if value == 'email':
            return AuthProvider.EMAIL
        raise ValueError('provider must be one of: email, google, apple')


@router.post('/sessions', summary='Sign in and create a session')
def sign_in(payload: SignInIn, request: Request, db: Session = Depends(get_db)):
    try:
        provider = payload.normalized_provider()
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc

    if provider == AuthProvider.EMAIL:
        if not payload.email:
            raise HTTPException(422, 'Email is required for email sign-in.')
        email = normalize_email(str(payload.email))
        enforce_limit(db, 'signin', email, client_ip(request))
        user = db.query(User).filter(User.email == email, User.auth_provider == provider).first()
        if not payload.password:
            raise HTTPException(422, 'Password is required for email sign-in.')
        if not user or not verify_password(user.password_hash if user else '', payload.password):
            raise HTTPException(401, 'Email or password is incorrect.')
        if user.account_status == AccountStatus.DISABLED:
            raise HTTPException(403, 'This account is inactive.')
        if user.account_status != AccountStatus.ACTIVE or not user.email_verified_at:
            raise HTTPException(403, 'Verify your email address before signing in.')
        if password_hash_needs_rehash(user.password_hash):
            user.password_hash = hash_password(payload.password)
    else:
        if not payload.id_token:
            raise HTTPException(422, f'An {provider.value.title()} ID token is required.')
        if not payload.nonce:
            raise HTTPException(422, 'A sign-in nonce is required.')
        enforce_limit(
            db,
            'signin',
            digest_secret(payload.id_token, 'social-signin-rate'),
            client_ip(request),
        )
        identity = verify_provider_id_token(provider, payload.id_token, payload.nonce, db)
        user = (
            db.query(User)
            .filter(
                User.auth_provider == provider,
                User.provider_user_id == identity.provider_user_id,
            )
            .first()
        )
        if not user:
            raise HTTPException(401, 'No account is registered for this social identity.')
        if user.account_status == AccountStatus.DISABLED:
            raise HTTPException(403, 'This account is inactive.')
        if user.account_status != AccountStatus.ACTIVE or not user.email_verified_at:
            raise HTTPException(403, 'This account is not active.')

    provider = user.auth_provider.value if hasattr(user.auth_provider, 'value') else user.auth_provider
    token = random_token()
    expires = now_utc() + timedelta(days=get_settings().session_ttl_days)
    db.add(AuthSession(user_id=user.user_id, token_digest=digest_secret(token, 'session'), expires_at=expires))
    db.commit()
    return {'access_token': token, 'token_type': 'bearer', 'expires_at': expires.isoformat(), 'user': {'email': user.email, 'first_name': user.first_name, 'provider': provider}}
