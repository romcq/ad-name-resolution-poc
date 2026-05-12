"""Small parsing helpers used by LDAP and Kerberos resolver steps."""

from __future__ import annotations

import re


SID_RE = re.compile(r"^S-\d+(?:-\d+)+$", re.IGNORECASE)
GUID_RE = re.compile(
    r"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$"
)
DN_RDN_RE = re.compile(r"(?i)^(CN|OU|DC|O|STREET|L|ST|C|UID)=")


def norm(value: str | None) -> str:
    return (value or "").strip().casefold()


def norm_guid(value: str | None) -> str:
    return norm(value).strip("{}")


def split_upn(value: str) -> tuple[str, str] | None:
    if value.count("@") != 1:
        return None
    account, suffix = value.split("@", 1)
    if not account or not suffix:
        return None
    return account, suffix


def split_downlevel(value: str) -> tuple[str, str] | None:
    if value.count("\\") != 1:
        return None
    domain, account = value.split("\\", 1)
    if not domain or not account:
        return None
    return domain, account


def is_guid(value: str) -> bool:
    return bool(GUID_RE.match(value.strip()))


def is_sid(value: str) -> bool:
    return bool(SID_RE.match(value.strip()))


def split_ldap_dn(value: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for char in value:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if char == ",":
            part = "".join(current).strip()
            if not part:
                return []
            parts.append(part)
            current = []
            continue
        current.append(char)
    if escaped:
        return []
    final_part = "".join(current).strip()
    if final_part:
        parts.append(final_part)
    return parts


def looks_like_dn(value: str) -> bool:
    parts = split_ldap_dn(value)
    if not parts:
        return False
    return all("=" in part for part in parts) and any(DN_RDN_RE.match(part) for part in parts)


def looks_like_canonical(value: str) -> bool:
    if "/" not in value or "\n" in value:
        return False
    first_segment = value.split("/", 1)[0]
    return "." in first_segment and bool(first_segment.strip())


def looks_like_canonical_lf(value: str) -> bool:
    if "\n" not in value:
        return False
    first_segment = value.split("/", 1)[0].split("\n", 1)[0]
    return "." in first_segment and bool(first_segment.strip())


def canonical_with_lf(canonical_name: str) -> str:
    left, separator, right = canonical_name.rpartition("/")
    if not separator:
        return canonical_name
    return f"{left}\n{right}"


def looks_like_spn(value: str) -> bool:
    if "/" not in value or "\n" in value:
        return False
    if looks_like_canonical(value):
        return False
    service, instance = value.split("/", 1)
    return bool(service.strip()) and bool(instance.strip())
