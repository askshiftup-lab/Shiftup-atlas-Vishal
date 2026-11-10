from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import AccountStatus, EmailVerification, User, get_db
from app.email_service import deliver
from app.rate_limiting.service import enforce_limit
from app.registrations.router import invalidate_otp, issue_otp, record_otp_sent
from app.security import client_ip, digest_secret, normalize_email, now_utc

router = APIRouter()


class EmailIn(BaseModel):
    email: EmailStr


class ConfirmIn(EmailIn):
    code: str

    @field_validator('code')
    @classmethod
    def validate_code_format(cls, value: str) -> str:
        digits = get_settings().otp_digits
        if len(value) != digits or not value.isascii() or not value.isdigit():
            raise ValueError(f'Code must contain exactly {digits} digits.')
        return value


def issue_and_send(db: Session, user: User) -> str:
    settings = get_settings()
    otp = issue_otp(db, user)
    db.commit()
    try:
        channel = deliver(user.email, 'Your email verification code', f'Your verification code is {otp}. It expires in {settings.otp_ttl_minutes} minutes.')
    except RuntimeError as exc:
        invalidate_otp(db, otp)
        raise HTTPException(503, 'The verification email could not be sent. Please try again later.') from exc
    record_otp_sent(db, otp)
    return channel


@router.post('/email-verifications', status_code=202, summary='Request an email verification code')
def request_code(payload: EmailIn, request: Request, db: Session = Depends(get_db)):
    generic_message = 'If this account needs verification, a code will be sent.'
    email = normalize_email(str(payload.email))
    enforce_limit(db, 'otp-request', email, client_ip(request))
    user = db.query(User).filter(User.email == email).with_for_update().first()
    if user and user.account_status == AccountStatus.PENDING and not user.email_verified_at:
        issue_and_send(db, user)
    return {'message': generic_message}


@router.post('/email-verifications/resend', status_code=202, summary='Resend a verification code')
def resend_code(payload: EmailIn, request: Request, db: Session = Depends(get_db)):
    generic_message = 'If this account needs verification, a new code will be sent.'
    email = normalize_email(str(payload.email))
    enforce_limit(db, 'otp-resend', email, client_ip(request))
    user = db.query(User).filter(User.email == email).with_for_update().first()
    if not user or user.account_status != AccountStatus.PENDING or user.email_verified_at:
        return {'message': generic_message}
    recent = db.query(EmailVerification).filter(EmailVerification.user_id == user.user_id).order_by(EmailVerification.created_at.desc()).first()
    cooldown = get_settings().otp_resend_cooldown_seconds
    if recent and recent.created_at > now_utc() - timedelta(seconds=cooldown):
        return {'message': generic_message}
    issue_and_send(db, user)
    return {'message': generic_message}


@router.post('/email-verifications/confirm', summary='Confirm an email verification code')
def confirm_code(payload: ConfirmIn, request: Request, db: Session = Depends(get_db)):
    email = normalize_email(str(payload.email))
    enforce_limit(db, 'otp-confirm', email, client_ip(request))
    user = db.query(User).filter(User.email == email).with_for_update().first()
    if not user or user.account_status != AccountStatus.PENDING or user.email_verified_at:
        raise HTTPException(400, 'The code is invalid or expired.')
    record = db.query(EmailVerification).filter(EmailVerification.user_id == user.user_id, EmailVerification.consumed_at.is_(None)).order_by(EmailVerification.created_at.desc()).with_for_update().first()
    if not record or record.expires_at <= now_utc() or record.attempts >= get_settings().otp_max_attempts:
        raise HTTPException(400, 'The code is invalid or expired.')
    if record.token_digest != digest_secret(payload.code, 'email-otp'):
        record.attempts += 1
        if record.attempts >= get_settings().otp_max_attempts:
            record.consumed_at = now_utc()
        db.commit()
        raise HTTPException(400, 'Wrong OTP entered.')
    record.consumed_at = now_utc()
    user.email_verified_at = now_utc()
    user.account_status = AccountStatus.ACTIVE
    db.commit()
    return {'message': 'Email verified. You can now sign in.', 'email': user.email}
