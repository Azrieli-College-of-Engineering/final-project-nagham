"""
Simple in-memory rate limiting utilities.

Provides per-IP rate limiting without external dependencies.
"""

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Deque, Dict


class RateLimitError(Exception):
    """Raised when a client exceeds the configured rate limit."""


_REQUESTS: Dict[str, Deque[datetime]] = defaultdict(deque)


def check_rate_limit(
    ip: str,
    *,
    limit: int = 20,
    window_seconds: int = 60,
) -> None:
    """
    Enforce a simple sliding-window rate limit per IP address.

    Args:
        ip: Client IP address.
        limit: Maximum number of requests allowed within the window.
        window_seconds: Window size in seconds.

    Raises:
        RateLimitError: If the client exceeds the configured limit.
    """
    if not ip:
        # Treat missing IP as a separate bucket to avoid bypass.
        ip = "unknown"

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=window_seconds)

    history = _REQUESTS[ip]

    # Drop entries that are outside the current window.
    while history and history[0] < window_start:
        history.popleft()

    if len(history) >= limit:
        raise RateLimitError(f"Rate limit exceeded for IP: {ip}")

    history.append(now)

