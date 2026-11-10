import hashlib
import hmac
import ipaddress
import re
import secrets
from datetime import UTC, datetime
from functools import lru_cache

import phonenumbers
from argon2 import PasswordHasher
from argon2.exceptions import Argon2Error, InvalidHashError
from email_validator import EmailNotValidError, validate_email
from fastapi import HTTPException, Request

from app.config import get_settings

@lru_cache
def _password_hasher() -> PasswordHasher:
    settings = get_settings()
    return PasswordHasher(
        time_cost=settings.password_hash_time_cost,
        memory_cost=settings.password_hash_memory_cost,
        parallelism=settings.password_hash_parallelism,
        hash_len=settings.password_hash_length,
        salt_len=settings.password_salt_length,
    )


def normalize_email(value: str) -> str:
    try:
        return validate_email(value.strip(), check_deliverability=False).normalized.lower()
    except EmailNotValidError as exc:
        raise HTTPException(422, 'Enter a valid email address.') from exc


def normalize_phone(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None

    candidate = value.strip()
    candidate = candidate.replace(' ', '').replace('-', '').replace('(', '').replace(')', '')
    if not candidate:
        return None

    if candidate.startswith('+'):
        cleaned = candidate
        region = None
    else:
        cleaned = candidate
        region = 'IN'

    if not cleaned.startswith('+') and not cleaned.isdigit():
        raise HTTPException(422, 'Enter a valid phone number with a country code.')
    if cleaned.startswith('+') and not cleaned[1:].isdigit():
        raise HTTPException(422, 'Enter a valid phone number with a country code.')
    if len(re.sub(r'\D', '', cleaned)) > 15:
        raise HTTPException(422, 'Enter a valid international phone number.')

    try:
        number = phonenumbers.parse(cleaned, region)
    except phonenumbers.NumberParseException as exc:
        raise HTTPException(422, 'Enter a valid international phone number.') from exc
    if not phonenumbers.is_possible_number(number) or not phonenumbers.is_valid_number(number):
        raise HTTPException(422, 'Enter a valid international phone number.')
    return phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)


def validate_password(value: str) -> str:
    settings = get_settings()
    requirements = (
        (settings.password_require_uppercase, r'[A-Z]', 'an uppercase letter'),
        (settings.password_require_number, r'\d', 'a number'),
        (settings.password_require_special, r'[^A-Za-z0-9]', 'a special character'),
    )
    missing = [description for required, pattern, description in requirements if required and not re.search(pattern, value)]
    if not settings.password_min_length <= len(value) <= settings.password_max_length or missing:
        requirement_text = ', '.join(settings.password_requirements())
        message = f'Password must be {settings.password_min_length}–{settings.password_max_length} characters'
        if requirement_text:
            message += f' and include {requirement_text}'
        raise HTTPException(422, message + '.')
    return value


def hash_password(password: str) -> str:
    return _password_hasher().hash(password)


def password_hash_needs_rehash(encoded: str) -> bool:
    return _password_hasher().check_needs_rehash(encoded)


def verify_password(encoded: str, password: str) -> bool:
    try:
        return _password_hasher().verify(encoded, password)
    except (Argon2Error, InvalidHashError, VerifyError):
        return False


# Argon2 exceptions differ slightly across versions; this alias is defined explicitly for safe verification.
try:
    from argon2.exceptions import VerifyMismatchError as VerifyError
except ImportError:
    VerifyError = Argon2Error


def random_token() -> str:
    return secrets.token_urlsafe(get_settings().token_bytes)


def digest_secret(value: str, purpose: str = 'token') -> str:
    key = get_settings().app_secret.encode()
    return hmac.new(key, f'{purpose}:{value}'.encode(), hashlib.sha256).hexdigest()


def now_utc() -> datetime:
    return datetime.now(UTC)


def client_ip(request: Request) -> str:
    peer = request.client.host if request.client else 'unknown'
    settings = get_settings()
    if not settings.trusted_proxy_cidrs:
        return peer
    try:
        address = ipaddress.ip_address(peer)
        trusted = [ipaddress.ip_network(item.strip()) for item in settings.trusted_proxy_cidrs.split(',') if item.strip()]
        if any(address in network for network in trusted):
            forwarded = request.headers.get('x-forwarded-for', '').split(',')[0].strip()
            return str(ipaddress.ip_address(forwarded))
    except ValueError:
        pass
    return peer
