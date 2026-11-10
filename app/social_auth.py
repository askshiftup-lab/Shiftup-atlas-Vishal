import hashlib
import hmac
from dataclasses import dataclass
from datetime import timedelta
from functools import lru_cache

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientError, PyJWTError
from sqlalchemy import update
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import AuthProvider, OAuthChallenge, get_db
from app.rate_limiting.service import enforce_limit
from app.security import client_ip, digest_secret, normalize_email, now_utc, random_token

router = APIRouter()


@dataclass(frozen=True)
class VerifiedIdentity:
    email: str | None
    first_name: str
    provider_user_id: str


_PROVIDER_SETTINGS = {
    AuthProvider.GOOGLE: {
        'issuer': {'accounts.google.com', 'https://accounts.google.com'},
        'jwks_url': 'https://www.googleapis.com/oauth2/v3/certs',
        'audiences_setting': 'google_client_ids',
    },
    AuthProvider.APPLE: {
        'issuer': {'https://appleid.apple.com'},
        'jwks_url': 'https://appleid.apple.com/auth/keys',
        'audiences_setting': 'apple_client_ids',
    },
}


@lru_cache(maxsize=2)
def _jwks_client(provider: AuthProvider) -> PyJWKClient:
    return PyJWKClient(_PROVIDER_SETTINGS[provider]['jwks_url'], timeout=5)


class SocialChallengeIn(BaseModel):
    provider: str


def _provider_from_input(value: str) -> AuthProvider:
    normalized = value.strip().lower()
    if normalized in {'google', 'gmail'}:
        return AuthProvider.GOOGLE
    if normalized in {'apple', 'ios'}:
        return AuthProvider.APPLE
    raise HTTPException(422, 'provider must be google or apple.')


@router.post('/social/challenges', status_code=201, summary='Create a one-time social sign-in nonce')
def create_social_challenge(
    payload: SocialChallengeIn,
    request: Request,
    db: Session = Depends(get_db),
):
    provider = _provider_from_input(payload.provider)
    settings = get_settings()
    audience_setting = _PROVIDER_SETTINGS[provider]['audiences_setting']
    if not any(item.strip() for item in getattr(settings, audience_setting).split(',')):
        raise HTTPException(503, f'{provider.value.title()} sign-in is not configured.')

    enforce_limit(db, 'social-challenge', provider.value, client_ip(request))
    now = now_utc()
    db.query(OAuthChallenge).filter(OAuthChallenge.expires_at <= now).delete(
        synchronize_session=False,
    )
    nonce = random_token()
    expires_at = now + timedelta(minutes=settings.social_auth_nonce_ttl_minutes)
    db.add(
        OAuthChallenge(
            auth_provider=provider,
            nonce_digest=digest_secret(nonce, f'oauth-nonce:{provider.value}'),
            expires_at=expires_at,
        )
    )
    db.commit()
    provider_nonce = (
        hashlib.sha256(nonce.encode()).hexdigest()
        if provider == AuthProvider.APPLE
        else nonce
    )
    return {
        'provider': provider.value,
        'nonce': nonce,
        'provider_nonce': provider_nonce,
        'expires_at': expires_at.isoformat(),
    }


def verify_provider_id_token(
    provider: AuthProvider,
    token: str,
    nonce: str,
    db: Session,
) -> VerifiedIdentity:
    provider_settings = _PROVIDER_SETTINGS.get(provider)
    if provider_settings is None:
        raise ValueError(f'ID-token verification is unsupported for {provider.value!r}')

    settings = get_settings()
    audiences = [
        item.strip()
        for item in getattr(settings, provider_settings['audiences_setting']).split(',')
        if item.strip()
    ]
    if not audiences:
        raise HTTPException(503, f'{provider.value.title()} sign-in is not configured.')

    try:
        signing_key = _jwks_client(provider).get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=['RS256'],
            audience=audiences,
            options={
                'require': ['exp', 'iat', 'iss', 'sub', 'aud'],
            },
            leeway=30,
        )
    except PyJWKClientError as exc:
        raise HTTPException(503, f'{provider.value.title()} identity verification is temporarily unavailable.') from exc
    except PyJWTError as exc:
        raise HTTPException(401, 'The social identity token is invalid or expired.') from exc

    if claims.get('iss') not in provider_settings['issuer']:
        raise HTTPException(401, 'The social identity token is invalid or expired.')
    audiences_claim = claims.get('aud')
    authorized_party = claims.get('azp')
    if (
        isinstance(audiences_claim, list)
        and len(audiences_claim) > 1
        and authorized_party not in audiences
    ) or (authorized_party is not None and authorized_party not in audiences):
        raise HTTPException(401, 'The social identity token is invalid or expired.')
    expected_nonce = (
        hashlib.sha256(nonce.encode()).hexdigest()
        if provider == AuthProvider.APPLE
        else nonce
    )
    if not isinstance(claims.get('nonce'), str) or not hmac.compare_digest(claims['nonce'], expected_nonce):
        raise HTTPException(401, 'The social identity token does not match the sign-in request.')

    consumed_at = now_utc()
    challenge = db.execute(
        update(OAuthChallenge)
        .where(
            OAuthChallenge.auth_provider == provider,
            OAuthChallenge.nonce_digest == digest_secret(nonce, f'oauth-nonce:{provider.value}'),
            OAuthChallenge.consumed_at.is_(None),
            OAuthChallenge.expires_at > consumed_at,
        )
        .values(consumed_at=consumed_at, updated_at=consumed_at)
        .execution_options(synchronize_session=False)
    )
    if challenge.rowcount != 1:
        db.rollback()
        raise HTTPException(401, 'The social sign-in request is invalid or expired.')
    db.commit()

    subject = claims.get('sub')
    email_claim = claims.get('email')
    if not isinstance(subject, str) or not subject:
        raise HTTPException(401, 'The social identity token is missing required identity claims.')
    if email_claim is not None and not isinstance(email_claim, str):
        raise HTTPException(401, 'The social identity token contains an invalid email address.')
    email = normalize_email(email_claim) if email_claim else None
    email_verified = claims.get('email_verified')
    verified_email = email_verified is True or (
        isinstance(email_verified, str) and email_verified.lower() == 'true'
    )
    if email and not verified_email:
        raise HTTPException(401, 'The social identity provider has not verified this email address.')
    name = claims.get('name')
    fallback_name = email.split('@', 1)[0] if email else provider.value.title()
    first_name = name.strip().split()[0] if isinstance(name, str) and name.strip() else fallback_name
    return VerifiedIdentity(email=email, first_name=first_name[:100], provider_user_id=subject)
