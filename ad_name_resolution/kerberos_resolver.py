"""Kerberos principal resolver over already parsed AS-REQ/TGS-REQ fields.

В этом файле нет парсинга ASN.1/pcap. На вход уже приходит структура, похожая
на то, что дал бы parser трафика: message_type, realm и cname/sname principal.
Дальше код повторяет ветки Client Principal Lookup и Server Principal Lookup.
"""

from __future__ import annotations

from .models import ResolutionResult, found_result, not_found_result, not_unique_result, unsupported_result
from .repository import ADSnapshotRepository
from .utils import split_downlevel, split_upn

CLIENT_BRANCH = "Client Principal Lookup"
SERVER_BRANCH = "Server Principal Lookup"

# Числовые Kerberos name-type, которые используются в тестах и статье.
NT_PRINCIPAL = 1
NT_SRV_INST = 2
NT_SRV_HST = 3
NT_ENTERPRISE = 10

NAME_TYPE_NAMES = {
    NT_PRINCIPAL: "NT-PRINCIPAL",
    NT_SRV_INST: "NT-SRV-INST",
    NT_SRV_HST: "NT-SRV-HST",
    NT_ENTERPRISE: "NT-ENTERPRISE",
}


def resolve_kerberos(event: dict, repository: ADSnapshotRepository) -> ResolutionResult:
    # Верхний Kerberos-роутер: AS-REQ разбирает client principal (cname),
    # TGS-REQ разбирает server principal (sname).
    message_type = (event.get("message_type") or "").upper()
    if message_type == "AS-REQ":
        return resolve_kerberos_as_req(event, repository)
    if message_type == "TGS-REQ":
        return resolve_kerberos_tgs_req(event, repository)
    return unsupported_result(protocol="Kerberos", reason="unsupported_kerberos_message_type")


def resolve_kerberos_as_req(event: dict, repository: ADSnapshotRepository) -> ResolutionResult:
    # AS-REQ: берем cname.name-type, cname.name-string[] и realm.
    # realm не выводится из строки имени, потому что в трафике это отдельное поле.
    principal = event.get("cname") or {}
    realm = event.get("realm")
    name_type = principal.get("name_type")
    components = list(principal.get("name_string") or [])
    input_value = _principal_to_string(components)
    trace: list[dict] = []
    if not components or not isinstance(name_type, int):
        return unsupported_result(protocol="Kerberos", algorithm_branch=CLIENT_BRANCH, input_field="cname", input_value=input_value, reason="invalid_input", trace=trace)
    if name_type == NT_ENTERPRISE:
        # KRB5-NT-ENTERPRISE-PRINCIPAL: обычно UPN-like строка.
        return _resolve_as_nt_enterprise(components, realm, repository, trace)
    if name_type == NT_PRINCIPAL:
        # KRB5-NT-PRINCIPAL: обычно один компонент с account name.
        return _resolve_as_nt_principal(components, realm, repository, trace)
    trace.append({"branch": CLIENT_BRANCH, "name_type": name_type, "supported": False})
    return unsupported_result(
        protocol="Kerberos",
        algorithm_branch=CLIENT_BRANCH,
        input_field="cname",
        input_value=input_value,
        reason="unsupported_name_type",
        notes=[f"name_type={name_type} is not implemented for AS-REQ in this prototype"],
        trace=trace,
    )


def resolve_kerberos_tgs_req(event: dict, repository: ADSnapshotRepository) -> ResolutionResult:
    # TGS-REQ: берем sname.name-type, sname.name-string[] и realm.
    # Здесь ищем сервисный объект/аккаунт, а не пользователя-клиента.
    principal = event.get("sname") or {}
    realm = event.get("realm")
    name_type = principal.get("name_type")
    components = list(principal.get("name_string") or [])
    input_value = _principal_to_string(components)
    trace: list[dict] = []
    if not components or not isinstance(name_type, int):
        return unsupported_result(protocol="Kerberos", algorithm_branch=SERVER_BRANCH, input_field="sname", input_value=input_value, reason="invalid_input", trace=trace)
    if name_type in {NT_PRINCIPAL, NT_SRV_INST, NT_SRV_HST}:
        # Эти типы идут по общей service-like ветке Server Principal Lookup.
        return _resolve_tgs_service_like(name_type, components, realm, repository, trace)
    if name_type == NT_ENTERPRISE:
        # NT-ENTERPRISE для sname идет по отдельной ветке: сначала SPN,
        # затем fallback на account name с проверкой наличия зарегистрированного SPN.
        return _resolve_tgs_nt_enterprise(components, realm, repository, trace)
    trace.append({"branch": SERVER_BRANCH, "name_type": name_type, "supported": False})
    return unsupported_result(
        protocol="Kerberos",
        algorithm_branch=SERVER_BRANCH,
        input_field="sname",
        input_value=input_value,
        reason="unsupported_name_type",
        notes=[f"name_type={name_type} is not implemented for TGS-REQ in this prototype"],
        trace=trace,
    )


def _resolve_as_nt_enterprise(
    components: list[str],
    realm: str | None,
    repository: ADSnapshotRepository,
    trace: list[dict],
) -> ResolutionResult:
    input_value = _principal_to_string(components)
    if len(components) != 1:
        return unsupported_result(protocol="Kerberos", algorithm_branch=CLIENT_BRANCH, input_field="cname", input_value=input_value, reason="unsupported_principal_shape", trace=trace)
    value = components[0]
    # AS NT-ENTERPRISE step 1-2: явный UPN, затем generated UPN.
    # Custom UPN suffix допускается: строка ищется как целый userPrincipalName.
    result = _match_upn_variant("Kerberos", CLIENT_BRANCH, "cname", input_value, "NT-ENTERPRISE", value, repository, realm, trace)
    if result is not None:
        return result
    parts = split_upn(value)
    if parts is not None:
        account, suffix = parts
        realm_domain = repository.domain_fqdn_for_context(realm)
        if realm_domain and suffix.casefold() == realm_domain.casefold():
            # AS NT-ENTERPRISE fallback: если suffix совпал с realm-доменом,
            # левую часть можно попробовать как sAMAccountName и account + "$".
            for fmt, account_value in [
                ("NT-ENTERPRISE/sAMAccountName", account),
                ("NT-ENTERPRISE/sAMAccountName+$", f"{account}$"),
            ]:
                result = _match_sam("Kerberos", CLIENT_BRANCH, "cname", input_value, fmt, account_value, realm, repository, trace)
                if result is not None:
                    return result
    # Если прямые проверки не нашли объект, по статье дальше возможен CrackNames.
    # В PoC он не реализован, поэтому явно отмечается в результате.
    return not_found_result(protocol="Kerberos", algorithm_branch=CLIENT_BRANCH, input_field="cname", input_value=input_value, unimplemented_steps=["CrackNames"], trace=trace)


def _resolve_as_nt_principal(
    components: list[str],
    realm: str | None,
    repository: ADSnapshotRepository,
    trace: list[dict],
) -> ResolutionResult:
    input_value = _principal_to_string(components)
    if len(components) != 1:
        return unsupported_result(protocol="Kerberos", algorithm_branch=CLIENT_BRANCH, input_field="cname", input_value=input_value, reason="unsupported_principal_shape", trace=trace)
    value = components[0]
    downlevel = split_downlevel(value)
    if downlevel is not None:
        # Если в NT-PRINCIPAL неожиданно пришел DOMAIN\user, домен переводим
        # в realm/domain context, а дальше ищем уже только account.
        domain, value = downlevel
        realm = repository.domain_fqdn_for_context(domain)
    # AS NT-PRINCIPAL: сначала sAMAccountName, затем machine-account вариант
    # с "$", затем UPN-вариант account@realm-domain.
    for fmt, account in [
        ("NT-PRINCIPAL/sAMAccountName", value),
        ("NT-PRINCIPAL/sAMAccountName+$", f"{value}$"),
    ]:
        result = _match_sam("Kerberos", CLIENT_BRANCH, "cname", input_value, fmt, account, realm, repository, trace)
        if result is not None:
            return result
    domain_fqdn = repository.domain_fqdn_for_context(realm)
    if domain_fqdn:
        result = _match_upn_variant("Kerberos", CLIENT_BRANCH, "cname", input_value, "NT-PRINCIPAL", f"{value}@{domain_fqdn}", repository, realm, trace)
        if result is not None:
            return result
    return not_found_result(protocol="Kerberos", algorithm_branch=CLIENT_BRANCH, input_field="cname", input_value=input_value, unimplemented_steps=["CrackNames"], trace=trace)


def _resolve_tgs_service_like(
    name_type: int,
    components: list[str],
    realm: str | None,
    repository: ADSnapshotRepository,
    trace: list[dict],
) -> ResolutionResult:
    input_value = _principal_to_string(components)
    type_name = NAME_TYPE_NAMES[name_type]
    if len(components) == 2 and components[0].casefold() == "krbtgt":
        # Special case krbtgt/service-realm: второй компонент используется
        # как sAMAccountName в контексте realm.
        result = _match_sam("Kerberos", SERVER_BRANCH, "sname", input_value, f"{type_name}/krbtgt/sAMAccountName", components[1], realm, repository, trace)
        if result is not None:
            return result
    service_string = _principal_to_string(components)
    # Для NT-PRINCIPAL/NT-SRV-INST/NT-SRV-HST service-string проверяется через
    # userPrincipalName, а не прямым поиском по servicePrincipalName.
    matches = repository.find_user_principal_name(service_string, realm)
    trace.append({"branch": SERVER_BRANCH, "step": f"{type_name}/service-string-as-userPrincipalName", "lookup_field": "userPrincipalName", "lookup_value": service_string, "matched_count": len(matches)})
    result = _resolve_matches("Kerberos", SERVER_BRANCH, "sname", input_value, f"{type_name}/userPrincipalName", "userPrincipalName", service_string, matches, trace)
    if result is not None:
        return result
    if len(components) == 1:
        # Fallback на sAMAccountName разрешен только для одноэлементного sname.
        value = components[0]
        for fmt, account in [(f"{type_name}/sAMAccountName", value), (f"{type_name}/sAMAccountName+$", f"{value}$")]:
            result = _match_sam("Kerberos", SERVER_BRANCH, "sname", input_value, fmt, account, realm, repository, trace)
            if result is not None:
                return result
    return not_found_result(protocol="Kerberos", algorithm_branch=SERVER_BRANCH, input_field="sname", input_value=input_value, trace=trace)


def _resolve_tgs_nt_enterprise(
    components: list[str],
    realm: str | None,
    repository: ADSnapshotRepository,
    trace: list[dict],
) -> ResolutionResult:
    input_value = _principal_to_string(components)
    if len(components) != 1:
        return unsupported_result(protocol="Kerberos", algorithm_branch=SERVER_BRANCH, input_field="sname", input_value=input_value, reason="unsupported_principal_shape", trace=trace)
    value = components[0]
    # TGS NT-ENTERPRISE: сначала трактуем строку как SPN.
    result = _match_spn(input_value, "NT-ENTERPRISE/servicePrincipalName", value, realm, repository, trace)
    if result is not None:
        return result
    for fmt, account in [("NT-ENTERPRISE/sAMAccountName", value), ("NT-ENTERPRISE/sAMAccountName+$", f"{value}$")]:
        matches = repository.find_sam_in_domain(account, realm)
        trace.append({"branch": SERVER_BRANCH, "step": fmt, "lookup_field": "sAMAccountName", "lookup_value": account, "matched_count": len(matches)})
        if not matches:
            continue
        # Если fallback нашел account, нужно дополнительно проверить, что у него
        # есть хотя бы один зарегистрированный SPN. Без этого lookup считается
        # неуспешным для server principal.
        spn_ready = [match for match in matches if match.servicePrincipalName]
        trace.append({"branch": SERVER_BRANCH, "step": f"{fmt}/registered-SPN-check", "lookup_field": "servicePrincipalName", "lookup_value": "any registered SPN on matched account", "matched_count": len(spn_ready)})
        result = _resolve_matches("Kerberos", SERVER_BRANCH, "sname", input_value, fmt, "sAMAccountName", account, spn_ready, trace)
        if result is not None:
            return result
    return not_found_result(protocol="Kerberos", algorithm_branch=SERVER_BRANCH, input_field="sname", input_value=input_value, trace=trace)


def _match_upn_variant(
    protocol: str,
    branch: str,
    input_field: str,
    input_value: str,
    format_prefix: str,
    value: str,
    repository: ADSnapshotRepository,
    domain_context: str | None,
    trace: list[dict],
) -> ResolutionResult | None:
    parts = split_upn(value)
    if parts is None:
        trace.append({"branch": branch, "step": f"{format_prefix}/UPN-variant", "syntax_match": False, "lookup_value": value})
        return None
    explicit_matches = repository.find_user_principal_name(value, domain_context)
    trace.append({"branch": branch, "step": f"{format_prefix}/userPrincipalName", "syntax_match": True, "lookup_field": "userPrincipalName", "lookup_value": value, "matched_count": len(explicit_matches)})
    explicit = _resolve_matches(protocol, branch, input_field, input_value, f"{format_prefix}/userPrincipalName", "userPrincipalName", value, explicit_matches, trace)
    if explicit is not None:
        return explicit
    account, suffix = parts
    # generated UPN работает только для объектов без explicit userPrincipalName.
    generated_matches = repository.find_generated_upn(account, suffix, domain_context)
    trace.append({"branch": branch, "step": f"{format_prefix}/generatedUPN", "syntax_match": True, "lookup_field": "sAMAccountName+domainFQDN", "lookup_value": value, "matched_count": len(generated_matches)})
    return _resolve_matches(protocol, branch, input_field, input_value, f"{format_prefix}/generatedUPN", "sAMAccountName+domainFQDN", value, generated_matches, trace)


def _match_sam(
    protocol: str,
    branch: str,
    input_field: str,
    input_value: str,
    matched_format: str,
    account: str,
    domain: str | None,
    repository: ADSnapshotRepository,
    trace: list[dict],
) -> ResolutionResult | None:
    # Общая helper-функция для Kerberos account lookup по sAMAccountName.
    matches = repository.find_sam_in_domain(account, domain)
    trace.append({"branch": branch, "step": matched_format, "lookup_field": "sAMAccountName", "lookup_value": account, "matched_count": len(matches)})
    return _resolve_matches(protocol, branch, input_field, input_value, matched_format, "sAMAccountName", account, matches, trace)


def _match_spn(
    input_value: str,
    matched_format: str,
    value: str,
    domain: str | None,
    repository: ADSnapshotRepository,
    trace: list[dict],
) -> ResolutionResult | None:
    # Прямой поиск строки по servicePrincipalName.
    matches = repository.find_service_principal_name(value, domain)
    trace.append({"branch": SERVER_BRANCH, "step": matched_format, "lookup_field": "servicePrincipalName", "lookup_value": value, "matched_count": len(matches)})
    return _resolve_matches("Kerberos", SERVER_BRANCH, "sname", input_value, matched_format, "servicePrincipalName", value, matches, trace)


def _resolve_matches(
    protocol: str,
    branch: str,
    input_field: str,
    input_value: str,
    matched_format: str,
    matched_field: str,
    matched_value: str,
    matches,
    trace: list[dict],
) -> ResolutionResult | None:
    # Единое правило для Kerberos-шагов: 0 -> продолжаем ветку,
    # 1 -> found, несколько -> not_unique без публикации candidate ids.
    if not matches:
        return None
    if len(matches) == 1:
        return found_result(
            protocol=protocol,
            algorithm_branch=branch,
            input_field=input_field,
            input_value=input_value,
            matched_format=matched_format,
            matched_field=matched_field,
            matched_value=matched_value,
            obj=matches[0],
            trace=trace,
        )
    return not_unique_result(
        protocol=protocol,
        algorithm_branch=branch,
        input_field=input_field,
        input_value=input_value,
        matched_format=matched_format,
        matched_field=matched_field,
        matched_value=matched_value,
        candidates=matches,
        trace=trace,
    )


def _principal_to_string(components: list[str]) -> str:
    return "/".join(str(component) for component in components)
