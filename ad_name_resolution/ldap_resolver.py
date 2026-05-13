"""LDAP Simple Bind resolver.

Здесь реализован порядок LDAP-проверок из статьи. Важный момент: это именно
последовательный алгоритм. Если строка похожа сразу на несколько форматов,
побеждает первый формат из списка, который дал ровно одно совпадение.
"""

from __future__ import annotations

from collections.abc import Callable

from .models import ResolutionResult, found_result, not_found_result, not_unique_result, unsupported_result
from .repository import ADSnapshotRepository
from .utils import (
    is_guid,
    is_sid,
    looks_like_canonical,
    looks_like_canonical_lf,
    looks_like_dn,
    looks_like_spn,
    split_downlevel,
    split_upn,
)

LDAP_BRANCH = "LDAP Simple Authentication"
LDAP_INPUT_FIELD = "LDAPMessage.protocolOp.bindRequest.name"


def resolve_ldap_simple_bind(
    event: dict,
    repository: ADSnapshotRepository,
    spn_mappings: dict[str, list[str]],
) -> ResolutionResult:
    request = event.get("request") or {}
    if request.get("operation") != "bindRequest":
        return unsupported_result(protocol="LDAP", algorithm_branch=LDAP_BRANCH, reason="unsupported_ldap_operation")

    input_value = request.get("name")
    if not isinstance(input_value, str) or not input_value.strip():
        return unsupported_result(
            protocol="LDAP",
            algorithm_branch=LDAP_BRANCH,
            input_field=LDAP_INPUT_FIELD,
            reason="invalid_input",
        )

    name = input_value.strip()
    domain_context = event.get("domain_context")
    trace: list[dict] = []

    # Порядок ниже повторяет LDAP Simple Authentication order.
    # Каждый шаг сам решает:
    # 1. подходит ли строка синтаксически под формат;
    # 2. сколько объектов найдено в snapshot;
    # 3. можно ли вернуть результат или нужно идти дальше.
    ordered_steps: list[Callable[[], ResolutionResult | None]] = [
        lambda: match_distinguished_name(name, repository, trace),
        lambda: match_upn_or_generated_upn(name, repository, domain_context, trace),
        lambda: match_down_level_logon_name(name, repository, trace),
        lambda: match_canonical_name(name, repository, trace),
        lambda: match_object_guid(name, repository, trace),
        lambda: match_display_name(name, repository, domain_context, trace),
        lambda: match_service_principal_name(name, repository, domain_context, trace),
        lambda: match_map_spn(name, repository, spn_mappings, domain_context, trace),
        lambda: match_object_sid(name, repository, trace),
        lambda: match_sid_history(name, repository, trace),
        lambda: match_canonical_name_lf(name, repository, trace),
    ]
    for step in ordered_steps:
        result = step()
        if result is not None:
            # Если шаг вернул found/not_unique, дальше форматы уже не проверяем.
            # Это и есть "победа более раннего формата".
            return result
    return not_found_result(
        protocol="LDAP",
        algorithm_branch=LDAP_BRANCH,
        input_field=LDAP_INPUT_FIELD,
        input_value=name,
        detected_format=_first_detected_ldap_format(trace),
        trace=trace,
    )


def _resolve_matches(
    *,
    input_value: str,
    matched_format: str,
    matched_field: str,
    matched_value: str,
    matches,
    trace: list[dict],
) -> ResolutionResult | None:
    # Единое правило для всех LDAP-шагов:
    # 0 совпадений -> формат не сработал, проверяем следующий;
    # 1 совпадение -> объект найден;
    # несколько совпадений -> stable result reason=not_unique.
    if not matches:
        return None
    if len(matches) == 1:
        return found_result(
            protocol="LDAP",
            algorithm_branch=LDAP_BRANCH,
            input_field=LDAP_INPUT_FIELD,
            input_value=input_value,
            matched_format=matched_format,
            matched_field=matched_field,
            matched_value=matched_value,
            obj=matches[0],
            trace=trace,
        )
    return not_unique_result(
        protocol="LDAP",
        algorithm_branch=LDAP_BRANCH,
        input_field=LDAP_INPUT_FIELD,
        input_value=input_value,
        matched_format=matched_format,
        matched_field=matched_field,
        matched_value=matched_value,
        candidates=matches,
        trace=trace,
    )


def _trace(trace: list[dict], **item) -> None:
    # Trace не является стабильным API-результатом. Он нужен, чтобы руками
    # увидеть, какие проверки выполнялись и сколько совпадений дала каждая.
    trace.append(item)


def _first_detected_ldap_format(trace: list[dict]) -> str | None:
    # For a not-found result we still want to tell the operator which input
    # format was recognized syntactically before the AD lookup returned zero.
    for item in trace:
        if item.get("syntax_match") is True:
            return item.get("step")
    return None


def match_distinguished_name(name: str, repository: ADSnapshotRepository, trace: list[dict]) -> ResolutionResult | None:
    # LDAP step 1: distinguishedName. Проверяется первым, поэтому DN выигрывает
    # даже если такая же строка где-то записана как displayName.
    if not looks_like_dn(name):
        _trace(trace, step="distinguishedName", syntax_match=False)
        return None
    matches = repository.find_distinguished_name(name)
    _trace(trace, step="distinguishedName", syntax_match=True, lookup_field="distinguishedName", lookup_value=name, matched_count=len(matches))
    return _resolve_matches(input_value=name, matched_format="distinguishedName", matched_field="distinguishedName", matched_value=name, matches=matches, trace=trace)


def match_upn_or_generated_upn(
    name: str,
    repository: ADSnapshotRepository,
    domain_context: str | None,
    trace: list[dict],
) -> ResolutionResult | None:
    # LDAP step 2: UPN-like строка. Сначала ищем явный userPrincipalName.
    # Если его нет, пробуем generated UPN: sAMAccountName@domainFQDN, но только
    # для объектов без явно заданного userPrincipalName.
    parts = split_upn(name)
    if parts is None:
        _trace(trace, step="userPrincipalName/generatedUPN", syntax_match=False)
        return None
    explicit_matches = repository.find_user_principal_name(name, domain_context)
    _trace(trace, step="userPrincipalName", syntax_match=True, lookup_field="userPrincipalName", lookup_value=name, matched_count=len(explicit_matches))
    explicit = _resolve_matches(input_value=name, matched_format="userPrincipalName", matched_field="userPrincipalName", matched_value=name, matches=explicit_matches, trace=trace)
    if explicit is not None:
        return explicit
    account, suffix = parts
    generated_matches = repository.find_generated_upn(account, suffix, domain_context)
    _trace(trace, step="generatedUPN", syntax_match=True, lookup_field="sAMAccountName+domainFQDN", lookup_value=f"{account}@{suffix}", matched_count=len(generated_matches))
    return _resolve_matches(input_value=name, matched_format="generatedUPN", matched_field="sAMAccountName+domainFQDN", matched_value=f"{account}@{suffix}", matches=generated_matches, trace=trace)


def match_down_level_logon_name(name: str, repository: ADSnapshotRepository, trace: list[dict]) -> ResolutionResult | None:
    # LDAP step 3: DOMAIN\account. DOMAIN сравнивается с domainNetBIOS,
    # account сравнивается с sAMAccountName.
    parts = split_downlevel(name)
    if parts is None:
        _trace(trace, step="downLevelLogonName", syntax_match=False)
        return None
    domain, account = parts
    matches = repository.find_downlevel(domain, account)
    _trace(trace, step="downLevelLogonName", syntax_match=True, lookup_field="domainNetBIOS+sAMAccountName", lookup_value=name, matched_count=len(matches))
    return _resolve_matches(input_value=name, matched_format="downLevelLogonName", matched_field="domainNetBIOS+sAMAccountName", matched_value=name, matches=matches, trace=trace)


def match_canonical_name(name: str, repository: ADSnapshotRepository, trace: list[dict]) -> ResolutionResult | None:
    # LDAP step 4: canonicalName вида domain.tld/OU/name.
    if not looks_like_canonical(name):
        _trace(trace, step="canonicalName", syntax_match=False)
        return None
    matches = repository.find_canonical_name(name)
    _trace(trace, step="canonicalName", syntax_match=True, lookup_field="canonicalName", lookup_value=name, matched_count=len(matches))
    return _resolve_matches(input_value=name, matched_format="canonicalName", matched_field="canonicalName", matched_value=name, matches=matches, trace=trace)


def match_object_guid(name: str, repository: ADSnapshotRepository, trace: list[dict]) -> ResolutionResult | None:
    # LDAP step 5: objectGUID. Скобки вокруг GUID допускаются.
    if not is_guid(name):
        _trace(trace, step="objectGUID", syntax_match=False)
        return None
    matches = repository.find_object_guid(name)
    _trace(trace, step="objectGUID", syntax_match=True, lookup_field="objectGUID", lookup_value=name, matched_count=len(matches))
    return _resolve_matches(input_value=name, matched_format="objectGUID", matched_field="objectGUID", matched_value=name, matches=matches, trace=trace)


def match_display_name(
    name: str,
    repository: ADSnapshotRepository,
    domain_context: str | None,
    trace: list[dict],
) -> ResolutionResult | None:
    # LDAP step 6: displayName проверяется поздно. Поэтому UPN/DN/canonicalName
    # выигрывают у displayName, но displayName все еще выигрывает у SPN/SID.
    matches = repository.find_display_name(name, domain_context)
    _trace(trace, step="displayName", syntax_match=True, lookup_field="displayName", lookup_value=name, matched_count=len(matches))
    return _resolve_matches(input_value=name, matched_format="displayName", matched_field="displayName", matched_value=name, matches=matches, trace=trace)


def match_service_principal_name(
    name: str,
    repository: ADSnapshotRepository,
    domain_context: str | None,
    trace: list[dict],
) -> ResolutionResult | None:
    # LDAP step 7: прямой поиск по servicePrincipalName.
    if not looks_like_spn(name):
        _trace(trace, step="servicePrincipalName", syntax_match=False)
        return None
    matches = repository.find_service_principal_name(name, domain_context)
    _trace(trace, step="servicePrincipalName", syntax_match=True, lookup_field="servicePrincipalName", lookup_value=name, matched_count=len(matches))
    return _resolve_matches(input_value=name, matched_format="servicePrincipalName", matched_field="servicePrincipalName", matched_value=name, matches=matches, trace=trace)


def match_map_spn(
    name: str,
    repository: ADSnapshotRepository,
    spn_mappings: dict[str, list[str]],
    domain_context: str | None,
    trace: list[dict],
) -> ResolutionResult | None:
    # LDAP step 8: упрощенный MapSPN. В реальном AD это богаче, здесь же
    # используется локальный словарь spn_mappings из ad_snapshot.json.
    if not looks_like_spn(name):
        _trace(trace, step="MapSPN", syntax_match=False)
        return None
    matches, mapped_value = repository.find_mapped_spn(name, spn_mappings, domain_context)
    if mapped_value is None:
        _trace(trace, step="MapSPN", syntax_match=True, lookup_field="servicePrincipalName", lookup_value=None, matched_count=0, note="no local mapping matched")
        return None
    _trace(trace, step="MapSPN", syntax_match=True, lookup_field="servicePrincipalName", lookup_value=mapped_value, matched_count=len(matches))
    return _resolve_matches(input_value=name, matched_format="MapSPN", matched_field="servicePrincipalName", matched_value=mapped_value, matches=matches, trace=trace)


def match_object_sid(name: str, repository: ADSnapshotRepository, trace: list[dict]) -> ResolutionResult | None:
    # LDAP step 9: текущий objectSid объекта.
    if not is_sid(name):
        _trace(trace, step="objectSid", syntax_match=False)
        return None
    matches = repository.find_object_sid(name)
    _trace(trace, step="objectSid", syntax_match=True, lookup_field="objectSid", lookup_value=name, matched_count=len(matches))
    return _resolve_matches(input_value=name, matched_format="objectSid", matched_field="objectSid", matched_value=name, matches=matches, trace=trace)


def match_sid_history(name: str, repository: ADSnapshotRepository, trace: list[dict]) -> ResolutionResult | None:
    # LDAP step 10: исторические SID из sIDHistory.
    if not is_sid(name):
        _trace(trace, step="sIDHistory", syntax_match=False)
        return None
    matches = repository.find_sid_history(name)
    _trace(trace, step="sIDHistory", syntax_match=True, lookup_field="sIDHistory", lookup_value=name, matched_count=len(matches))
    return _resolve_matches(input_value=name, matched_format="sIDHistory", matched_field="sIDHistory", matched_value=name, matches=matches, trace=trace)


def match_canonical_name_lf(name: str, repository: ADSnapshotRepository, trace: list[dict]) -> ResolutionResult | None:
    # LDAP step 11: вариант canonicalName, где последний "/" представлен как LF.
    if not looks_like_canonical_lf(name):
        _trace(trace, step="canonicalNameWithLF", syntax_match=False)
        return None
    matches = repository.find_canonical_name_lf(name)
    _trace(trace, step="canonicalNameWithLF", syntax_match=True, lookup_field="canonicalName", lookup_value=name, matched_count=len(matches))
    return _resolve_matches(input_value=name, matched_format="canonicalNameWithLF", matched_field="canonicalName", matched_value=name, matches=matches, trace=trace)
