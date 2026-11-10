from datetime import timedelta
from html import escape as escape_html
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import update
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import AccountStatus, AuthProvider, AuthSession, PasswordReset, User, get_db
from app.email_service import deliver
from app.rate_limiting.service import enforce_limit
from app.security import client_ip, digest_secret, hash_password, normalize_email, now_utc, random_token, validate_password

router = APIRouter()


class ResetRequestIn(BaseModel):
    email: EmailStr


class ResetConfirmIn(BaseModel):
    token: str = Field(min_length=20, max_length=200)
    new_password: str
    confirm_password: str


@router.post('/password-resets', status_code=202, summary='Request a password-reset email')
def request_reset(payload: ResetRequestIn, request: Request, db: Session = Depends(get_db)):
    email = normalize_email(str(payload.email))
    enforce_limit(db, 'reset-request', email, client_ip(request))
    user = db.query(User).filter(
        User.email == email,
        User.account_status == AccountStatus.ACTIVE,
        User.auth_provider == AuthProvider.EMAIL,
        User.email_verified_at.is_not(None),
    ).with_for_update().first()
    if not user:
        return {'message': 'If an eligible account exists, a password reset email will be sent.'}
    now = now_utc()
    db.query(PasswordReset).filter(
        PasswordReset.user_id == user.user_id,
        PasswordReset.consumed_at.is_(None),
    ).update(
        {'consumed_at': now, 'updated_at': now},
        synchronize_session=False,
    )
    token = random_token()
    expires_at = now + timedelta(minutes=get_settings().password_reset_ttl_minutes)
    db.add(PasswordReset(user_id=user.user_id, token_digest=digest_secret(token, 'password-reset'), expires_at=expires_at))
    db.commit()
    url = f"{get_settings().password_reset_url}#{urlencode({'reset_token': token})}"
    expiry_minutes = get_settings().password_reset_ttl_minutes
    try:
        channel = deliver(
            user.email,
            'Reset your password',
            f'Use this one-time link within {expiry_minutes} minutes to reset your password:\n\n{url}\n\nIf you did not request this, you can ignore this email.',
            html_body=(
                '<p>We received a request to reset your password.</p>'
                f'<p><a href="{escape_html(url, quote=True)}">Reset your password</a></p>'
                f'<p>This one-time link expires in {expiry_minutes} minutes and can be used once.</p>'
                '<p>If you did not request this, you can ignore this email.</p>'
            ),
        )
    except RuntimeError as exc:
        failed_at = now_utc()
        db.query(PasswordReset).filter(
            PasswordReset.user_id == user.user_id,
            PasswordReset.token_digest == digest_secret(token, 'password-reset'),
            PasswordReset.consumed_at.is_(None),
        ).update(
            {'consumed_at': failed_at, 'updated_at': failed_at},
            synchronize_session=False,
        )
        db.commit()
        raise HTTPException(503, 'Password reset email delivery failed. Please try again later.') from exc

    sent_at = now_utc()
    db.query(PasswordReset).filter(
        PasswordReset.user_id == user.user_id,
        PasswordReset.token_digest == digest_secret(token, 'password-reset'),
        PasswordReset.consumed_at.is_(None),
    ).update(
        {
            'expires_at': sent_at + timedelta(minutes=expiry_minutes),
            'updated_at': sent_at,
        },
        synchronize_session=False,
    )
    db.commit()
    message = (
        'If an eligible account exists, reset instructions are available in the development server log; no email was sent.'
        if channel == 'development-preview'
        else 'If an eligible account exists, reset instructions will be sent by email.'
    )
    return {'message': message}


@router.post('/password-resets/confirm', summary='Consume a reset token and set a new password')
def confirm_reset(payload: ResetConfirmIn, request: Request, db: Session = Depends(get_db)):
    enforce_limit(db, 'reset-confirm', digest_secret(payload.token, 'reset-rate-subject'), client_ip(request))
    password = validate_password(payload.new_password)
    if password != payload.confirm_password:
        raise HTTPException(422, 'Passwords do not match.')
    candidate = db.query(PasswordReset).filter(PasswordReset.token_digest == digest_secret(payload.token, 'password-reset')).first()
    if not candidate:
        raise HTTPException(400, 'The reset link is invalid or expired.')
    user = db.query(User).filter(User.user_id == candidate.user_id).with_for_update().first()
    record = db.query(PasswordReset).filter(PasswordReset.id == candidate.id).with_for_update().first()
    now = now_utc()
    if not record or record.consumed_at or record.expires_at <= now:
        raise HTTPException(400, 'The reset link is invalid or expired.')
    if not user or user.account_status == AccountStatus.DISABLED:
        raise HTTPException(400, 'The reset link is invalid or expired.')
    consumed = db.execute(
        update(PasswordReset)
        .where(
            PasswordReset.id == record.id,
            PasswordReset.consumed_at.is_(None),
            PasswordReset.expires_at > now,
        )
        .values(consumed_at=now, updated_at=now)
        .execution_options(synchronize_session=False)
    )
    if consumed.rowcount != 1:
        raise HTTPException(400, 'The reset link is invalid or expired.')
    user.password_hash = hash_password(password)
    db.query(AuthSession).filter(
        AuthSession.user_id == user.user_id,
        AuthSession.revoked_at.is_(None),
    ).update(
        {'revoked_at': now, 'updated_at': now},
        synchronize_session=False,
    )
    db.commit()
    return {'message': 'Password reset complete. Sign in with your new password.'}
