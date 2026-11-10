from datetime import timedelta

from fastapi import HTTPException
from sqlalchemy import DateTime, text
from sqlalchemy.orm import Session

from app.config import get_settings
from app.security import digest_secret, now_utc


def enforce_limit(db: Session, scope: str, subject: str, ip: str) -> None:
    now = now_utc()
    limit, window_seconds = get_settings().rate_limit_policy(scope)
    window = timedelta(seconds=window_seconds)
    keys = [digest_secret(f'{scope}:subject:{subject}', 'rate-limit'), digest_secret(f'{scope}:ip:{ip}', 'rate-limit')]
    retry_after = 0
    for key in keys:
        statement = text('''
            INSERT INTO rate_limits (key_digest, window_started_at, request_count, created_at, updated_at)
            VALUES (:key, :now, 1, :now, :now)
            ON CONFLICT (key_digest) DO UPDATE SET
              window_started_at = CASE WHEN rate_limits.window_started_at <= :cutoff THEN :now ELSE rate_limits.window_started_at END,
              request_count = CASE WHEN rate_limits.window_started_at <= :cutoff THEN 1 ELSE rate_limits.request_count + 1 END,
              updated_at = :now
            RETURNING request_count, window_started_at
        ''').columns(window_started_at=DateTime(timezone=True))
        row = db.execute(statement, {'key': key, 'now': now, 'cutoff': now - window}).mappings().one()
        if row['request_count'] > limit:
            retry_after = max(retry_after, int((row['window_started_at'] + window - now).total_seconds()) + 1)
    db.commit()
    if retry_after:
        raise HTTPException(429, 'Too many requests. Please try again later.', headers={'Retry-After': str(retry_after)})
