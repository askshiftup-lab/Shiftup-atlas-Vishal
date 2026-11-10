from enum import StrEnum

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String, create_engine, event, func, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.types import TypeDecorator

from app.config import get_settings


class Base(DeclarativeBase):
    pass


class UTCDateTime(TypeDecorator):
    impl = DateTime(timezone=True)
    cache_ok = True

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        from datetime import UTC

        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class TimestampMixin:
    created_at: Mapped[object] = mapped_column(
        UTCDateTime(),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[object] = mapped_column(
        UTCDateTime(),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class AccountStatus(StrEnum):
    PENDING = 'pending'
    ACTIVE = 'active'
    DISABLED = 'disabled'


class AuthProvider(StrEnum):
    EMAIL = 'email'
    GOOGLE = 'google'
    APPLE = 'apple'


class User(TimestampMixin, Base):
    __tablename__ = 'users'
    __table_args__ = (
        CheckConstraint(
            "account_status IN ('pending', 'active', 'disabled')",
            name='ck_users_account_status',
        ),
        CheckConstraint(
            "auth_provider IN ('email', 'google', 'apple')",
            name='ck_users_auth_provider',
        ),
        CheckConstraint(
            'phone_number IS NULL OR length(phone_number) <= 16',
            name='ck_users_phone_number_length',
        ),
        Index('uq_users_email_normalized', text('lower(email)'), unique=True),
        Index(
            'uq_users_provider_identity',
            'auth_provider',
            'provider_user_id',
            unique=True,
            sqlite_where=text('provider_user_id IS NOT NULL'),
            postgresql_where=text('provider_user_id IS NOT NULL'),
        ),
    )

    user_id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(254), nullable=False)
    first_name: Mapped[str] = mapped_column(String(100), nullable=False)
    phone_number: Mapped[str | None] = mapped_column(String(16), nullable=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    auth_provider: Mapped[AuthProvider] = mapped_column(
        String(16),
        nullable=False,
        default=AuthProvider.EMAIL,
        server_default=AuthProvider.EMAIL.value,
    )
    provider_user_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    phone_verified_at: Mapped[object | None] = mapped_column(UTCDateTime(), nullable=True)
    email_verified_at: Mapped[object | None] = mapped_column(UTCDateTime(), nullable=True)
    account_status: Mapped[AccountStatus] = mapped_column(
        String(16),
        nullable=False,
        default=AccountStatus.PENDING,
        server_default=AccountStatus.PENDING.value,
    )


class EmailVerification(TimestampMixin, Base):
    __tablename__ = 'email_verifications'
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.user_id', ondelete='CASCADE'), index=True)
    token_digest: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    expires_at: Mapped[object] = mapped_column(UTCDateTime(), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    consumed_at: Mapped[object | None] = mapped_column(UTCDateTime(), nullable=True)


class AuthSession(TimestampMixin, Base):
    __tablename__ = 'auth_sessions'
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.user_id', ondelete='CASCADE'), index=True)
    token_digest: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    expires_at: Mapped[object] = mapped_column(UTCDateTime(), nullable=False)
    revoked_at: Mapped[object | None] = mapped_column(UTCDateTime(), nullable=True)


class PasswordReset(TimestampMixin, Base):
    __tablename__ = 'password_resets'
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.user_id', ondelete='CASCADE'), index=True)
    token_digest: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    expires_at: Mapped[object] = mapped_column(UTCDateTime(), nullable=False)
    consumed_at: Mapped[object | None] = mapped_column(UTCDateTime(), nullable=True)


class OAuthChallenge(TimestampMixin, Base):
    __tablename__ = 'oauth_challenges'
    __table_args__ = (
        CheckConstraint(
            "auth_provider IN ('google', 'apple')",
            name='ck_oauth_challenges_provider',
        ),
        Index('ix_oauth_challenges_expires_at', 'expires_at'),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    auth_provider: Mapped[AuthProvider] = mapped_column(String(16), nullable=False)
    nonce_digest: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    expires_at: Mapped[object] = mapped_column(UTCDateTime(), nullable=False)
    consumed_at: Mapped[object | None] = mapped_column(UTCDateTime(), nullable=True)


class RateLimit(TimestampMixin, Base):
    __tablename__ = 'rate_limits'
    key_digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    window_started_at: Mapped[object] = mapped_column(UTCDateTime(), nullable=False)
    request_count: Mapped[int] = mapped_column(Integer, nullable=False)


settings = get_settings()
if settings.database_url.startswith('sqlite:///'):
    engine = create_engine(
        settings.database_url,
        pool_pre_ping=True,
        connect_args={'check_same_thread': False},
    )
else:
    engine = create_engine(
        settings.database_url,
        pool_pre_ping=True,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
    )
if settings.database_url.startswith('sqlite:///'):
    @event.listens_for(engine, 'connect')
    def enable_sqlite_foreign_keys(connection, _):
        cursor = connection.cursor()
        cursor.execute('PRAGMA foreign_keys=ON')
        cursor.close()

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
