"""Opt-in diagnostic logging that never echoes identity or authentication data.

The native messaging backend used to write complete request and response
payloads to stderr unconditionally. Those payloads can contain eID file
contents, activation tokens and signature material. This module keeps
troubleshooting output useful while making disclosure explicit and bounded.
"""

import json
import os

# Values of these keys are never written to stderr, even in debug mode.
# Matching is case-insensitive so both 'activationToken' and 'token' are covered.
SENSITIVE_KEYS = frozenset({
    'activationtoken',
    'challenge',
    'data',
    'hash',
    'key',
    'pin',
    'pincode',
    'privatekey',
    'secret',
    'signature',
    'token',
})

REDACTED = '<redacted>'
OMITTED = '<unparseable message omitted>'
TRUTHY = {'1', 'true', 'yes', 'on'}


def debug_enabled():
    """Return True only when the user explicitly opts in via CONNECTIVE_DEBUG."""
    return os.environ.get('CONNECTIVE_DEBUG', '').strip().lower() in TRUTHY


def _redact(value):
    """Recursively replace sensitive values while keeping the message shape."""
    if isinstance(value, dict):
        return {
            key: (REDACTED if str(key).strip().lower() in SENSITIVE_KEYS else _redact(item))
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    return value


def redact_native_message(text):
    """Return a loggable representation of a native messaging JSON payload.

    Unparseable input is replaced by a placeholder instead of being echoed:
    a truncated request may still contain identity data.
    """
    try:
        payload = json.loads(text)
    except (TypeError, ValueError):
        return OMITTED
    return json.dumps(_redact(payload), sort_keys=True)
