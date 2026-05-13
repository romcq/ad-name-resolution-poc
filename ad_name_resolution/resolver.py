from __future__ import annotations

from .kerberos_resolver import resolve_kerberos
from .ldap_resolver import resolve_ldap_simple_bind
from .models import ResolutionResult, invalid_input_result, unsupported_result
from .repository import ADSnapshotRepository


def resolve_event(
    event: dict,
    repository: ADSnapshotRepository,
    spn_mappings: dict[str, list[str]],
) -> ResolutionResult:
    # Это верхний роутер прототипа. Он не разбирает реальный трафик сам,
    # а получает уже нормализованное событие из JSON/CLI и выбирает нужный
    # алгоритм: LDAP Simple Bind или Kerberos AS/TGS.
    protocol = (event.get("protocol") or "").casefold()
    if protocol == "ldap":
        # В статье для LDAP нас интересует Simple Bind и поле BindRequest.name.
        # Другие LDAP-операции здесь явно не реализованы.
        bind_kind = (event.get("bind_kind") or "simple").casefold()
        if bind_kind != "simple":
            return unsupported_result(protocol="LDAP", reason="unsupported_bind_kind")
        return resolve_ldap_simple_bind(event, repository, spn_mappings)
    if protocol == "kerberos":
        # Для Kerberos событие уже должно содержать message_type и principal:
        # AS-REQ -> cname, TGS-REQ -> sname.
        return resolve_kerberos(event, repository)
    return invalid_input_result("unsupported_protocol")
