import logging

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)


def deliver(recipient: str, subject: str, body: str, html_body: str | None = None) -> str:
    settings = get_settings()
    if settings.resend_api_key and settings.resend_from_email:
        message = {
            'from': settings.resend_from_email,
            'to': [recipient],
            'subject': subject,
            'text': body,
        }
        if html_body:
            message['html'] = html_body
        try:
            response = httpx.post(
                settings.resend_api_url,
                headers={'Authorization': f'Bearer {settings.resend_api_key}', 'Content-Type': 'application/json'},
                json=message,
                timeout=settings.email_timeout_seconds,
            )
        except httpx.HTTPError as exc:
            raise RuntimeError('Email provider request failed') from exc
        if response.is_error:
            raise RuntimeError('Email provider rejected the message')
        return 'resend'
    if settings.app_env != 'development':
        raise RuntimeError('Email delivery is not configured outside development')
    logger.warning(
        'Development email preview only; no email was sent. recipient=%s subject=%s body=%s',
        recipient,
        subject,
        body,
    )
    return 'development-preview'
