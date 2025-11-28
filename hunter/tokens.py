"""
XJutsu v5 - HMAC Token System
Secure single-use tokens for payload serving
"""

import hmac
import hashlib
import time
import base64
from datetime import timedelta
from django.conf import settings
from django.utils import timezone


class TokenService:
    """
    HMAC-based token generation and verification
    """

    @staticmethod
    def get_secret_key():
        """Get signing key from settings"""
        return getattr(settings, 'XJUTSU_TOKEN_SECRET', settings.SECRET_KEY).encode()

    @classmethod
    def generate_token(cls, payload_id=None, expires_minutes=60):
        """
        Generate a signed token
        Format: base64(payload_id:timestamp:signature)
        """
        timestamp = int(time.time())
        expires = timestamp + (expires_minutes * 60)

        payload_str = str(payload_id) if payload_id else 'default'
        message = f"{payload_str}:{expires}"

        signature = hmac.new(
            cls.get_secret_key(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()[:16]

        token_data = f"{payload_str}:{expires}:{signature}"
        token = base64.urlsafe_b64encode(token_data.encode()).decode().rstrip('=')

        return token

    @classmethod
    def verify_token(cls, token):
        """
        Verify a token and return payload_id if valid
        Returns: (is_valid, payload_id, error_message)
        """
        try:
            # Pad base64 if needed
            padding = 4 - (len(token) % 4)
            if padding != 4:
                token += '=' * padding

            token_data = base64.urlsafe_b64decode(token.encode()).decode()
            parts = token_data.split(':')

            if len(parts) != 3:
                return False, None, "Invalid token format"

            payload_str, expires_str, signature = parts
            expires = int(expires_str)

            # Check expiry
            if time.time() > expires:
                return False, None, "Token expired"

            # Verify signature
            message = f"{payload_str}:{expires_str}"
            expected_sig = hmac.new(
                cls.get_secret_key(),
                message.encode(),
                hashlib.sha256
            ).hexdigest()[:16]

            if not hmac.compare_digest(signature, expected_sig):
                return False, None, "Invalid signature"

            payload_id = None if payload_str == 'default' else payload_str
            return True, payload_id, None

        except Exception as e:
            return False, None, f"Token error: {str(e)}"

    @classmethod
    def generate_short_token(cls, length=8):
        """
        Generate a short random token (for simpler use cases)
        """
        import secrets
        return secrets.token_urlsafe(length)[:length]


class RateLimiter:
    """
    Simple in-memory rate limiter (use Redis in production)
    """
    _cache = {}

    @classmethod
    def check_rate_limit(cls, key, max_requests=10, window_seconds=60):
        """
        Check if request is within rate limit
        Returns: (is_allowed, remaining, reset_time)
        """
        now = time.time()
        window_start = now - window_seconds

        # Clean old entries
        if key in cls._cache:
            cls._cache[key] = [t for t in cls._cache[key] if t > window_start]
        else:
            cls._cache[key] = []

        current_count = len(cls._cache[key])

        if current_count >= max_requests:
            reset_time = min(cls._cache[key]) + window_seconds
            return False, 0, reset_time

        cls._cache[key].append(now)
        remaining = max_requests - current_count - 1

        return True, remaining, now + window_seconds

    @classmethod
    def get_client_key(cls, request, prefix='rate'):
        """Get rate limit key from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', 'unknown')

        return f"{prefix}:{ip}"
