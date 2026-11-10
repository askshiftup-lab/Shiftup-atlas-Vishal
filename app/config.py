from functools import lru_cache
from urllib.parse import parse_qs, urlparse

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', env_file_encoding='utf-8', extra='ignore')

    app_env: str = 'development'
    app_secret: str = 'local-development-only-change-me'
    database_url: str = 'sqlite:///./auth_dev.db'
    password_reset_url: str = 'http://127.0.0.1:3000/password-reset'
    server_host: str = '127.0.0.1'
    server_port: int = Field(default=8000, ge=1, le=65535)
    server_reload: bool = True
    resend_api_key: str = ''
    resend_from_email: str = ''
    resend_api_url: str = 'https://api.resend.com/emails'
    email_timeout_seconds: float = Field(default=10, gt=0, le=120)
    google_client_ids: str = ''
    apple_client_ids: str = ''
    social_auth_nonce_ttl_minutes: int = Field(default=5, ge=1, le=10)
    trusted_proxy_cidrs: str = ''
    session_ttl_days: int = Field(default=30, ge=1, le=3650)
    password_min_length: int = Field(default=8, ge=1, le=128)
    password_max_length: int = Field(default=24, ge=1, le=128)
    password_require_uppercase: bool = True
    password_require_number: bool = True
    password_require_special: bool = True
    password_hash_time_cost: int = Field(default=3, ge=1, le=10)
    password_hash_memory_cost: int = Field(default=131072, ge=8192, le=1048576)
    password_hash_parallelism: int = Field(default=2, ge=1, le=16)
    password_hash_length: int = Field(default=24, ge=16, le=64)
    password_salt_length: int = Field(default=16, ge=16, le=64)
    token_bytes: int = Field(default=32, ge=32, le=128)
    otp_digits: int = Field(default=6, ge=6, le=6)
    otp_ttl_minutes: int = Field(default=10, ge=1, le=60)
    otp_max_attempts: int = Field(default=5, ge=1, le=20)
    otp_resend_cooldown_seconds: int = Field(default=60, ge=0, le=3600)
    password_reset_ttl_minutes: int = Field(default=10, ge=1, le=60)
    auth_rate_limit_window_seconds: int = Field(default=900, ge=1, le=86400)
    signup_rate_limit: int = Field(default=5, ge=1, le=1000)
    signin_rate_limit: int = Field(default=8, ge=1, le=1000)
    otp_request_rate_limit: int = Field(default=5, ge=1, le=1000)
    otp_resend_rate_limit: int = Field(default=4, ge=1, le=1000)
    otp_confirm_rate_limit: int = Field(default=10, ge=1, le=1000)
    reset_request_rate_limit: int = Field(default=5, ge=1, le=1000)
    reset_confirm_rate_limit: int = Field(default=10, ge=1, le=1000)
    social_challenge_rate_limit: int = Field(default=15, ge=1, le=1000)
    first_name_max_length: int = Field(default=100, ge=1, le=100)
    phone_input_max_length: int = Field(default=16, ge=8, le=16)
    db_pool_size: int = Field(default=5, ge=1, le=100)
    db_max_overflow: int = Field(default=10, ge=0, le=200)

    @model_validator(mode='after')
    def validate_password_lengths(self):
        if self.password_min_length > self.password_max_length:
            raise ValueError('PASSWORD_MIN_LENGTH must not exceed PASSWORD_MAX_LENGTH')
        return self

    @field_validator('app_env', mode='before')
    @classmethod
    def normalize_app_env(cls, value: str) -> str:
        normalized = str(value).strip().lower()
        return {'prod': 'production', 'dev': 'development'}.get(normalized, normalized)

    @field_validator('database_url')
    @classmethod
    def supported_database(cls, value: str) -> str:
        if not value.startswith(('postgresql+psycopg://', 'sqlite:///')):
            raise ValueError('DATABASE_URL must use PostgreSQL with psycopg or a SQLite file')
        return value

    @field_validator('phone_input_max_length')
    @classmethod
    def normalize_phone_input_max_length(cls, _value: int) -> int:
        return 16

    @field_validator(
        'password_reset_url',
        'resend_api_key',
        'resend_from_email',
        'resend_api_url',
        'google_client_ids',
        'apple_client_ids',
    )
    @classmethod
    def trim_email_settings(cls, value: str) -> str:
        return value.strip()

    def validate_runtime(self) -> None:
        if self.app_env not in {'development', 'production'}:
            raise RuntimeError('APP_ENV must be development or production')
        if bool(self.resend_api_key) != bool(self.resend_from_email):
            raise RuntimeError('RESEND_API_KEY and RESEND_FROM_EMAIL must be configured together')
        if self.app_env != 'development' and not self.resend_api_key:
            raise RuntimeError('Email delivery must be configured outside development')

        reset_url = urlparse(self.password_reset_url)
        if (
            reset_url.scheme not in {'http', 'https'}
            or not reset_url.netloc
            or reset_url.username
            or reset_url.password
            or reset_url.query
            or reset_url.fragment
        ):
            raise RuntimeError('PASSWORD_RESET_URL must be an absolute URL without a query or fragment')

        if self.app_env.lower() == 'production':
            if self.server_reload:
                raise RuntimeError('SERVER_RELOAD must be false in production')
            if self.password_min_length < 8:
                raise RuntimeError('Production PASSWORD_MIN_LENGTH must be at least 8')
            if (self.password_hash_time_cost < 3 or self.password_hash_memory_cost < 131072
                    or self.password_hash_parallelism < 2):
                raise RuntimeError(
                    'Production Argon2 settings must use time cost >= 3, memory cost >= 131072 KiB, '
                    'and parallelism >= 2'
                )
            if self.password_hash_length != 24:
                raise RuntimeError('Production PASSWORD_HASH_LENGTH must be 24 bytes')
            if self.otp_digits < 6:
                raise RuntimeError('Production OTP_DIGITS must be at least 6')
            if not self.database_url.startswith('postgresql+psycopg://'):
                raise RuntimeError('Production requires PostgreSQL with the psycopg driver')
            if (len(self.app_secret) < 32 or len(set(self.app_secret)) < 16
                    or self.app_secret == 'local-development-only-change-me' or 'REPLACE' in self.app_secret):
                raise RuntimeError('Production requires a unique APP_SECRET of at least 32 characters')
            if (not self.resend_api_key or not self.resend_from_email
                    or 'REPLACE' in self.resend_api_key.upper()
                    or 'REPLACE' in self.resend_from_email.upper()):
                raise RuntimeError('Production requires RESEND_API_KEY and a verified RESEND_FROM_EMAIL')
            if not self.google_client_ids or not self.apple_client_ids:
                raise RuntimeError('Production requires GOOGLE_CLIENT_IDS and APPLE_CLIENT_IDS')
            if 'REPLACE' in self.google_client_ids.upper() or 'REPLACE' in self.apple_client_ids.upper():
                raise RuntimeError('Production provider client IDs must not contain placeholders')
            resend_url = urlparse(self.resend_api_url)
            if resend_url.scheme != 'https' or not resend_url.netloc:
                raise RuntimeError('Production RESEND_API_URL must use HTTPS')
            if reset_url.scheme != 'https' or 'REPLACE' in self.password_reset_url.upper():
                raise RuntimeError('Production PASSWORD_RESET_URL must be an HTTPS client reset page')
            if 'localhost' in self.database_url or 'auth_dev' in self.database_url or 'REPLACE' in self.database_url.upper():
                raise RuntimeError('Production must not use local development database credentials')
            sslmode = parse_qs(urlparse(self.database_url).query).get('sslmode', [''])[0].lower()
            if sslmode not in {'require', 'verify-ca', 'verify-full'}:
                raise RuntimeError('Production DATABASE_URL must require PostgreSQL TLS using sslmode=require, verify-ca, or verify-full')

    def password_requirements(self) -> list[str]:
        requirements = []
        if self.password_require_uppercase:
            requirements.append('an uppercase letter')
        if self.password_require_number:
            requirements.append('a number')
        if self.password_require_special:
            requirements.append('a special character')
        return requirements

    def public_runtime_config(self) -> dict[str, object]:
        return {
            'password_min_length': self.password_min_length,
            'password_max_length': self.password_max_length,
            'password_require_uppercase': self.password_require_uppercase,
            'password_require_number': self.password_require_number,
            'password_require_special': self.password_require_special,
            'password_requirements': self.password_requirements(),
            'otp_digits': self.otp_digits,
            'otp_ttl_minutes': self.otp_ttl_minutes,
            'otp_max_attempts': self.otp_max_attempts,
            'otp_resend_cooldown_seconds': self.otp_resend_cooldown_seconds,
            'password_reset_ttl_minutes': self.password_reset_ttl_minutes,
            'first_name_max_length': self.first_name_max_length,
            'phone_input_max_length': self.phone_input_max_length,
        }

    def rate_limit_policy(self, scope: str) -> tuple[int, int]:
        limits = {
            'signup': self.signup_rate_limit,
            'signin': self.signin_rate_limit,
            'otp-request': self.otp_request_rate_limit,
            'otp-resend': self.otp_resend_rate_limit,
            'otp-confirm': self.otp_confirm_rate_limit,
            'reset-request': self.reset_request_rate_limit,
            'reset-confirm': self.reset_confirm_rate_limit,
            'social-challenge': self.social_challenge_rate_limit,
        }
        try:
            return limits[scope], self.auth_rate_limit_window_seconds
        except KeyError as exc:
            raise ValueError(f'No rate-limit settings exist for scope {scope!r}') from exc


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.validate_runtime()
    return settings
