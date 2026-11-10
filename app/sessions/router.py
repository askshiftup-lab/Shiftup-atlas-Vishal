from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.db import AccountStatus, AuthSession, User, get_db
from app.security import digest_secret, now_utc

router = APIRouter()
bearer = HTTPBearer(auto_error=False)


def authenticated_session(credentials: HTTPAuthorizationCredentials | None, db: Session) -> tuple[AuthSession, User]:
    if not credentials or credentials.scheme.lower() != 'bearer':
        raise HTTPException(401, 'A valid bearer session is required.', headers={'WWW-Authenticate': 'Bearer'})
    record = db.query(AuthSession).filter(AuthSession.token_digest == digest_secret(credentials.credentials, 'session')).first()
    if not record or record.revoked_at or record.expires_at <= now_utc():
        raise HTTPException(401, 'Session is invalid or expired.', headers={'WWW-Authenticate': 'Bearer'})
    user = db.query(User).filter(User.user_id == record.user_id).first()
    if not user or user.account_status != AccountStatus.ACTIVE or not user.email_verified_at:
        raise HTTPException(401, 'Session is invalid or expired.')
    return record, user


@router.get('/sessions/current', summary='Get the current authenticated identity')
def current_session(credentials: HTTPAuthorizationCredentials | None = Depends(bearer), db: Session = Depends(get_db)):
    record, user = authenticated_session(credentials, db)
    provider = user.auth_provider.value if hasattr(user.auth_provider, 'value') else user.auth_provider
    return {'user': {'user_id': user.user_id, 'email': user.email, 'first_name': user.first_name, 'phone_number': user.phone_number, 'phone_verified_at': user.phone_verified_at.isoformat() if user.phone_verified_at else None, 'email_verified': True, 'provider': provider}, 'session': {'expires_at': record.expires_at.isoformat(), 'created_at': record.created_at.isoformat()}}


@router.delete('/sessions/current', status_code=204, summary='Revoke the current session')
def revoke_current(credentials: HTTPAuthorizationCredentials | None = Depends(bearer), db: Session = Depends(get_db)):
    record, _ = authenticated_session(credentials, db)
    record.revoked_at = now_utc()
    db.commit()
