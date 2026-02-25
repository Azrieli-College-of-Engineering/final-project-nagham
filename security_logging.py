"""
Security-focused structured logging utilities for MetaGuard.

This module provides JSON-based logging helpers to ensure that
only non-sensitive, high-level security events are recorded.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional


logger = logging.getLogger("metaguard.security")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def _mask_ip(ip: Optional[str]) -> Optional[str]:
    """
    Mask the last octet of an IPv4 address to avoid logging full client IPs.

    Args:
        ip: Original IP address string.

    Returns:
        Masked IP address or None if input is invalid/empty.
    """
    if not ip:
        return None

    parts = ip.split(".")
    if len(parts) == 4:
        # IPv4: mask last octet
        parts[-1] = "x"
        return ".".join(parts)

    # For non-IPv4 (IPv6, etc.), avoid detailed logging
    return "***"


def log_security_event(
    event: str,
    *,
    ip: Optional[str] = None,
    file_type: Optional[str] = None,
    risk_level: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Log a structured security event as JSON.

    This function MUST NOT receive or log:
    - Raw metadata values
    - GPS coordinates
    - Full file system paths
    - File contents

    Args:
        event: Name of the security event (e.g., "file_analyzed").
        ip: Client IP address (will be masked before logging).
        file_type: High-level file type/extension (e.g., ".jpg").
        risk_level: Risk level if applicable ("Low", "Medium", "High").
        extra: Additional non-sensitive fields to include.
    """
    payload: Dict[str, Any] = {
        "event": event,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    masked_ip = _mask_ip(ip)
    if masked_ip is not None:
        payload["ip"] = masked_ip

    if file_type is not None:
        payload["file_type"] = file_type

    if risk_level is not None:
        payload["risk_level"] = risk_level

    if extra:
        # Ensure we never accidentally log sensitive nested fields
        safe_extra = {
            k: v
            for k, v in extra.items()
            if k
            not in {
                "metadata",
                "gps_coordinates",
                "file_path",
                "contents",
            }
        }
        payload.update(safe_extra)

    try:
        logger.info(json.dumps(payload, separators=(",", ":")))
    except Exception:
        # Logging should never break application flow
        pass

