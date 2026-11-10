from datetime import timedelta
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import AccountStatus, AuthProvider, EmailVerification, User, get_db
from app.email_service import deliver
from app.rate_limiting.service import enforce_limit
from app.security import client_ip, digest_secret, hash_password, normalize_email, normalize_phone, now_utc, validate_password
from app.social_auth import verify_provider_id_token

router = APIRouter()


class RegistrationIn(BaseModel):
    email: EmailStr | None = None
    first_name: str | None = Field(default=None, min_length=1, max_length=get_settings().first_name_max_length)
    password: str | None = None
    phone: str | None = Field(default=None, max_length=get_settings().phone_input_max_length)
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


def issue_otp(db: Session, user: User) -> str:
    settings = get_settings()
    now = now_utc()
    db.query(User.user_id).filter(User.user_id == user.user_id).with_for_update().one()
    db.query(EmailVerification).filter(EmailVerification.user_id == user.user_id, EmailVerification.consumed_at.is_(None)).update(
        {'consumed_at': now, 'updated_at': now},
        synchronize_session=False,
    )
    otp = f'{secrets.randbelow(10 ** settings.otp_digits):0{settings.otp_digits}d}'
    db.add(EmailVerification(user_id=user.user_id, token_digest=digest_secret(otp, 'email-otp'), expires_at=now + timedelta(minutes=settings.otp_ttl_minutes), attempts=0))
    db.flush()
    return otp


def record_otp_sent(db: Session, otp: str) -> None:
    sent_at = now_utc()
    verification = db.query(EmailVerification).filter(
        EmailVerification.token_digest == digest_secret(otp, 'email-otp'),
    ).with_for_update().first()
    if verification is None:
        db.rollback()
        raise RuntimeError('The verification record was missing after email delivery.')
    if verification.consumed_at is None:
        verification.expires_at = sent_at + timedelta(minutes=get_settings().otp_ttl_minutes)
        verification.updated_at = sent_at
    db.commit()


def invalidate_otp(db: Session, otp: str) -> None:
    invalidated_at = now_utc()
    db.query(EmailVerification).filter(
        EmailVerification.token_digest == digest_secret(otp, 'email-otp'),
        EmailVerification.consumed_at.is_(None),
    ).update(
        {'consumed_at': invalidated_at, 'updated_at': invalidated_at},
        synchronize_session=False,
    )
    db.commit()


@router.post('/registrations', status_code=202, summary='Create an account')
def register(payload: RegistrationIn, request: Request, db: Session = Depends(get_db)):
    try:
        provider = payload.normalized_provider()
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc

    phone = normalize_phone(payload.phone)

    if provider == AuthProvider.EMAIL:
        if not payload.email:
            raise HTTPException(422, 'Email is required for email sign-up.')
        email = normalize_email(str(payload.email))
        first_name = (payload.first_name or '').strip()
        if not first_name:
            raise HTTPException(422, 'First name is required.')
        if not payload.password:
            raise HTTPException(422, 'Password is required for email sign-up.')
        enforce_limit(db, 'signup', email, client_ip(request))
        if db.query(User.user_id).filter(User.email == email).first():
            return {'message': 'If this account can be created, next steps will be sent to its email address.'}

        password = validate_password(payload.password)
        password_hash = hash_password(password)
        user = User(
            email=email,
            first_name=first_name,
            phone_number=phone,
            password_hash=password_hash,
            auth_provider=provider,
            account_status=AccountStatus.PENDING,
            email_verified_at=None,
        )
        db.add(user)
        try:
            db.flush()
            otp = issue_otp(db, user)
            db.commit()
        except IntegrityError:
            db.rollback()
            return {'message': 'If this account can be created, next steps will be sent to its email address.'}
        try:
            deliver(email, 'Verify your email address', f'Your verification code is {otp}. It expires in {get_settings().otp_ttl_minutes} minutes.')
        except RuntimeError as exc:
            invalidate_otp(db, otp)
            raise HTTPException(503, 'Account created, but the verification email could not be sent. Please request a new code later.') from exc
        record_otp_sent(db, otp)
        return {'message': 'If this account can be created, next steps will be sent to its email address.'}

    if not payload.id_token:
        raise HTTPException(422, f'An {provider.value.title()} ID token is required.')
    if not payload.nonce:
        raise HTTPException(422, 'A sign-in nonce is required.')
    enforce_limit(
        db,
        'signup',
        digest_secret(payload.id_token, 'social-signup-rate'),
        client_ip(request),
    )
    identity = verify_provider_id_token(provider, payload.id_token, payload.nonce, db)
    if (
        db.query(User.user_id)
        .filter(
            User.auth_provider == provider,
            User.provider_user_id == identity.provider_user_id,
        )
        .first()
    ):
        return {'message': 'If this account can be created, next steps will be sent to its email address.'}
    if not identity.email:
        raise HTTPException(401, 'The provider did not supply a verified email address for account creation.')
    if db.query(User.user_id).filter(User.email == identity.email).first():
        return {'message': 'If this account can be created, next steps will be sent to its email address.'}

    user = User(
        email=identity.email,
        first_name=identity.first_name,
        phone_number=phone,
        password_hash=hash_password(secrets.token_urlsafe(32)),
        auth_provider=provider,
        provider_user_id=identity.provider_user_id,
        account_status=AccountStatus.ACTIVE,
        email_verified_at=now_utc(),
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        return {'message': 'If this account can be created, next steps will be sent to its email address.'}
    return {'message': 'If this account can be created, next steps will be sent to its email address.'}
