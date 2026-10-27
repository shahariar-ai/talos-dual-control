"""Secret detection, redaction and taint helpers.

Talos never writes raw secrets into its ledger. Secrets are replaced by a short
fingerprint (``«secret:ab12cd»``) so an auditor can still correlate two events
that touched the same secret without learning the secret itself.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Iterable

_KV = re.compile(r"(?im)^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*[=:]\s*(.+?)\s*$")

TOKEN_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_\-]{12,}"),  # OpenAI-style keys
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key id
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),  # GitHub tokens
    re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}"),  # Slack tokens
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # JWT
]
SECRET_KEY_NAMES = re.compile(r"(?i)(api[_-]?key|secret|token|passw(or)?d|passwd|private[_-]?key|credential)")


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:6]


def _strip_quotes(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    return v


def find_secrets(text: str) -> set[str]:
    """Return secret-looking values found in ``text``."""
    found: set[str] = set()
    for pat in TOKEN_PATTERNS:
        for m in pat.finditer(text):
            found.add(m.group(0))
    for m in _KV.finditer(text):
        key, val = m.group(1), _strip_quotes(m.group(2))
        if SECRET_KEY_NAMES.search(key) and len(val) >= 6:
            found.add(val)
    return found


def secret_values_from_env_file(text: str) -> set[str]:
    """Every value in a credential-style file is treated as tainted."""
    values: set[str] = set()
    for m in _KV.finditer(text):
        val = _strip_quotes(m.group(2))
        if len(val) >= 6:
            values.add(val)
    for line in text.splitlines():
        s = line.strip()
        if len(s) >= 20 and "=" not in s[:3] and " " not in s:  # key material body lines
            values.add(s)
    return values


def redact(text: str, extra: Iterable[str] = ()) -> str:
    vals = sorted(find_secrets(text) | set(extra), key=len, reverse=True)
    for v in vals:
        if v and v in text:
            text = text.replace(v, f"«secret:{fingerprint(v)}»")
    return text


def redact_obj(obj: Any, limit: int = 500) -> Any:
    if isinstance(obj, str):
        r = redact(obj)
        return r if len(r) <= limit else r[:limit] + f"…[+{len(r) - limit} chars]"
    if isinstance(obj, dict):
        return {k: redact_obj(v, limit) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact_obj(v, limit) for v in obj]
    return obj


def tainted_hits(text: str, tainted: Iterable[str]) -> list[str]:
    """Fingerprints of tainted values that appear inside ``text``."""
    return [fingerprint(t) for t in tainted if t and t in text]
