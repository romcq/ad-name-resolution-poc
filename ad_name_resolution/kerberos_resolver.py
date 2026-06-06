"""Резолвер Kerberos principal поверх уже разобранных полей AS-REQ/TGS-REQ.

В этом файле нет парсинга ASN.1/pcap. На вход уже приходит структура, похожая
на то, что дал бы parser трафика: message_type, realm и cname/sname principal.
Дальше код повторяет ветки Client Principal Lookup и Server Principal Lookup.
"""

from __future__ import annotations

from .models import ResolutionResult, found_result, not_found_result, not_unique_result, unsupported_result
from .repository import ADSnapshotRepository
from .utils import looks_like_dn, split_downlevel, split_upn

CLIENT_BRANCH = "Client Principal Lookup"
SERVER_BRANCH = "Server Principal Lookup"

# Числовые Kerberos name-type, которые используются в тестах и статье.
NT_UNKNOWN = 0
NT_PRINCIPAL = 1
NT_SRV_INST = 2
NT_SRV_HST = 3
NT_SRV_XHST = 4
NT_UID = 5
NT_X500_PRINCIPAL = 6
NT_SMTP_NAME = 7
NT_ENTERPRISE = 10
NT_WELLKNOWN = 11
NT_SRV_HST_DOMAIN = 12
NT_MS_PRINCIPAL = -128
NT_MS_PRINCIPAL_AND_ID = -129
NT_ENT_PRINCIPAL_AND_ID = -130

NAME_TYPE_NAMES = {
    NT_UNKNOWN: "NT-UNKNOWN",
    NT_PRINCIPAL: "NT-PRINCIPAL",
    NT_SRV_INST: "NT-SRV-INST",
    NT_SRV_HST: "NT-SRV-HST",
    NT_SRV_XHST: "NT-SRV-XHST",
    NT_UID: "NT-UID",
    NT_X500_PRINCIPAL: "NT-X500-PRINCIPAL",
    NT_SMTP_NAME: "NT-SMTP-NAME",
    NT_ENTERPRISE: "NT-ENTERPRISE",
    NT_WELLKNOWN: "NT-WELLKNOWN",
    NT_SRV_HST_DOMAIN: "NT-SRV-HST-DOMAIN",
    NT_MS_PRINCIPAL: "NT-MS-PRINCIPAL",
    NT_MS_PRINCIPAL_AND_ID: "NT-MS-PRINCIPAL-AND-ID",
    NT_ENT_PRINCIPAL_AND_ID: "NT-ENT-PRINCIPAL-AND-ID",
}

AS_ACCOUNT_NAME_TYPES = {
    NT_UNKNOWN,
    NT_PRINCIPAL,
    NT_SRV_HST,
    NT_SRV_XHST,
    NT_SMTP_NAME,
    NT_WELLKNOWN,
    NT_SRV_HST_DOMAIN,
}

SERVER_SERVICE_NAME_TYPES = {
    NT_UNKNOWN,
    NT_PRINCIPAL,
    NT_SRV_INST,
    NT_SRV_HST,
    NT_SRV_XHST,
    NT_SMTP_NAME,
    NT_WELLKNOWN,
    NT_SRV_HST_DOMAIN,
    NT_ENT_PRINCIPAL_AND_ID,
}

SERVER_ACCOUNT_NAME_TYPES = {
    NT_UNKNOWN,
    NT_PRINCIPAL,
    NT_SRV_INST,
    NT_SRV_HST,
    NT_SRV_XHST,
    NT_SMTP_NAME,
    NT_WELLKNOWN,
    NT_SRV_HST_DOMAIN,
}


def resolve_kerberos(event: dict, repository: ADSnapshotRepository) -> ResolutionResult:
    # Верхний Kerberos-роутер: AS-REQ обычно разбирает client principal (cname),
    # но KDC-прогон также проверяет AS-REQ sname как server principal.
    # TGS-REQ разбирает server principal (sname).
    message_type = (event.get("message_type") or "").upper()
    if message_type == "AS-REQ":
        if _event_targets_sname(event):
            return resolve_kerberos_as_req_sname(event, repository)
        return resolve_kerberos_as_req(event, repository)
    if message_type == "TGS-REQ":
        return resolve_kerberos_tgs_req(event, repository)
    return unsupported_result(protocol="Kerberos", reason="unsupported_kerberos_message_type")


def _event_targets_sname(event: dict) -> bool:
    # Existing tests and CLI AS-REQ events use cname. For KDC-derived AS sname
    # tests the event can either set principal_field=sname or simply omit cname.
    if (event.get("principal_field") or "").casefold() == "sname":
        return True
    return "sname" in event and "cname" not in event


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
    if _looks_like_ldap_dn_components(components):
        return unsupported_result(
            protocol="Kerberos",
            algorithm_branch=CLIENT_BRANCH,
            input_field="cname",
            input_value=input_value,
            reason="unsupported_kerberos_name_format",
            notes=["LDAP distinguishedName is not a Kerberos client principal format in this prototype"],
            trace=trace,
        )
    if name_type == NT_ENTERPRISE:
        # KRB5-NT-ENTERPRISE-PRINCIPAL: обычно UPN-like строка.
        return _resolve_as_nt_enterprise(components, realm, repository, trace)
    if name_type == NT_ENT_PRINCIPAL_AND_ID:
        # В активном KDC-прогоне этот тип ведет себя как enterprise-lookup
        # для UPN и дополнительно принимает DN.
        return _resolve_as_nt_enterprise(components, realm, repository, trace, "NT-ENT-PRINCIPAL-AND-ID")
    if name_type in AS_ACCOUNT_NAME_TYPES:
        # KRB5-NT-PRINCIPAL: обычно один компонент с account name.
        return _resolve_as_account_principal(name_type, components, realm, repository, trace)
    if name_type in {NT_MS_PRINCIPAL, NT_MS_PRINCIPAL_AND_ID}:
        # Microsoft principal types для UPN-like строки проверяют generated UPN,
        # а не explicit userPrincipalName. Это подтверждает conflict-case KDC.
        return _resolve_as_ms_principal(name_type, components, realm, repository, trace)
    if name_type == NT_X500_PRINCIPAL:
        return _resolve_as_x500_principal(components, realm, repository, trace)
    if name_type == NT_SRV_INST:
        return _resolve_as_srv_inst(components, realm, repository, trace)
    if name_type == NT_UID:
        return _not_found_for_name_type(CLIENT_BRANCH, "cname", name_type, components, trace)
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


def resolve_kerberos_as_req_sname(event: dict, repository: ADSnapshotRepository) -> ResolutionResult:
    # AS-REQ также содержит sname. Для прототипа это отдельный server-principal
    # lookup поверх уже выделенного поля, подтвержденный active KDC run.
    principal = event.get("sname") or {}
    realm = event.get("realm")
    name_type = principal.get("name_type")
    components = list(principal.get("name_string") or [])
    input_value = _principal_to_string(components)
    trace: list[dict] = []
    if not components or not isinstance(name_type, int):
        return unsupported_result(protocol="Kerberos", algorithm_branch=SERVER_BRANCH, input_field="sname", input_value=input_value, reason="invalid_input", trace=trace)
    if len(components) == 1 and _is_krbtgt_principal(components):
        result = _match_sam("Kerberos", SERVER_BRANCH, "sname", input_value, f"{NAME_TYPE_NAMES[name_type]}/krbtgt/sAMAccountName", "krbtgt", realm, repository, trace)
        if result is not None:
            return result
    if name_type in SERVER_SERVICE_NAME_TYPES:
        return _resolve_server_service_like(name_type, components, realm, repository, trace)
    if name_type in {NT_ENTERPRISE, NT_MS_PRINCIPAL, NT_MS_PRINCIPAL_AND_ID}:
        return _resolve_server_account_only(name_type, components, realm, repository, trace)
    if name_type == NT_UID:
        return _not_found_for_name_type(SERVER_BRANCH, "sname", name_type, components, trace)
    trace.append({"branch": SERVER_BRANCH, "name_type": name_type, "supported": False})
    return unsupported_result(
        protocol="Kerberos",
        algorithm_branch=SERVER_BRANCH,
        input_field="sname",
        input_value=input_value,
        reason="unsupported_name_type",
        notes=[f"name_type={name_type} is not implemented for AS-REQ sname in this prototype"],
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
    if _looks_like_ldap_dn_components(components):
        return unsupported_result(
            protocol="Kerberos",
            algorithm_branch=SERVER_BRANCH,
            input_field="sname",
            input_value=input_value,
            reason="unsupported_kerberos_name_format",
            notes=["LDAP distinguishedName is not a Kerberos server principal format in this prototype"],
            trace=trace,
        )
    if name_type in SERVER_SERVICE_NAME_TYPES:
        # Эти типы идут по общей service-like ветке Server Principal Lookup.
        return _resolve_server_service_like(name_type, components, realm, repository, trace)
    if name_type == NT_ENTERPRISE:
        # NT-ENTERPRISE для sname идет по отдельной ветке: сначала SPN,
        # затем fallback на account name с проверкой наличия зарегистрированного SPN.
        return _resolve_tgs_nt_enterprise(components, realm, repository, trace)
    if name_type in {NT_MS_PRINCIPAL, NT_MS_PRINCIPAL_AND_ID}:
        return _resolve_tgs_ms_principal(name_type, components, realm, repository, trace)
    if name_type == NT_UID:
        return _not_found_for_name_type(SERVER_BRANCH, "sname", name_type, components, trace)
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
    format_prefix: str = "NT-ENTERPRISE",
) -> ResolutionResult:
    input_value = _principal_to_string(components)
    if len(components) != 1:
        return unsupported_result(protocol="Kerberos", algorithm_branch=CLIENT_BRANCH, input_field="cname", input_value=input_value, reason="unsupported_principal_shape", trace=trace)
    value = components[0]
    if format_prefix == "NT-ENT-PRINCIPAL-AND-ID":
        result = _match_distinguished_name("Kerberos", CLIENT_BRANCH, "cname", input_value, format_prefix, value, repository, trace)
        if result is not None:
            return result
    # AS NT-ENTERPRISE step 1-2: сначала explicit UPN, затем generated/implicit UPN.
    # Custom UPN suffix допустим: полная строка сначала ищется как userPrincipalName,
    # и только потом resolver переходит к смыслу sAMAccountName@domainFQDN.
    result = _match_upn_variant("Kerberos", CLIENT_BRANCH, "cname", input_value, format_prefix, value, repository, realm, trace)
    if result is not None:
        return result
    downlevel = split_downlevel(value)
    if downlevel is not None:
        domain, account = downlevel
        domain_context = repository.domain_fqdn_for_context(domain)
        for fmt, account_value in [
            (f"{format_prefix}/downLevelLogonName", account),
            (f"{format_prefix}/downLevelLogonName+$", f"{account}$"),
        ]:
            result = _match_sam("Kerberos", CLIENT_BRANCH, "cname", input_value, fmt, account_value, domain_context, repository, trace)
            if result is not None:
                return result
        return not_found_result(
            protocol="Kerberos",
            algorithm_branch=CLIENT_BRANCH,
            input_field="cname",
            input_value=input_value,
            detected_format=f"{format_prefix}/downLevelLogonName",
            unimplemented_steps=["CrackNames"],
            trace=trace,
        )
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
                fmt = fmt.replace("NT-ENTERPRISE", format_prefix)
                result = _match_sam("Kerberos", CLIENT_BRANCH, "cname", input_value, fmt, account_value, realm, repository, trace)
                if result is not None:
                    return result
    if format_prefix == "NT-ENTERPRISE" and _is_simple_account_name(value):
        for fmt, account_value in [
            (f"{format_prefix}/sAMAccountName", value),
            (f"{format_prefix}/sAMAccountName+$", f"{value}$"),
        ]:
            result = _match_sam("Kerberos", CLIENT_BRANCH, "cname", input_value, fmt, account_value, realm, repository, trace)
            if result is not None:
                return result
    # Если прямые проверки не нашли объект, по статье дальше возможен CrackNames.
    # В рамках ITDR snapshot-модели отдельный CrackNames не реализуется:
    # полные идентификаторы уже ищутся по доступному AD snapshot, а короткие
    # имена остаются привязанными к realm/domain context.
    detected_format = f"{format_prefix}/userPrincipalName" if split_upn(value) else format_prefix
    return not_found_result(
        protocol="Kerberos",
        algorithm_branch=CLIENT_BRANCH,
        input_field="cname",
        input_value=input_value,
        detected_format=detected_format,
        unimplemented_steps=["CrackNames"],
        trace=trace,
    )


def _not_found_for_name_type(
    branch: str,
    input_field: str,
    name_type: int,
    components: list[str],
    trace: list[dict],
) -> ResolutionResult:
    input_value = _principal_to_string(components)
    type_name = NAME_TYPE_NAMES[name_type]
    if len(components) > 1:
        detected_format = f"{type_name}/servicePrincipalName"
    elif components and split_downlevel(components[0]):
        detected_format = f"{type_name}/downLevelLogonName"
    elif components and split_upn(components[0]):
        detected_format = f"{type_name}/userPrincipalName"
    elif components and looks_like_dn(components[0]):
        detected_format = f"{type_name}/distinguishedName"
    else:
        detected_format = f"{type_name}/sAMAccountName"
    trace.append({"branch": branch, "name_type": name_type, "supported_negative": True})
    return not_found_result(
        protocol="Kerberos",
        algorithm_branch=branch,
        input_field=input_field,
        input_value=input_value,
        detected_format=detected_format,
        trace=trace,
    )


def _resolve_as_ms_principal(
    name_type: int,
    components: list[str],
    realm: str | None,
    repository: ADSnapshotRepository,
    trace: list[dict],
) -> ResolutionResult:
    input_value = _principal_to_string(components)
    type_name = NAME_TYPE_NAMES[name_type]
    if len(components) != 1:
        return not_found_result(
            protocol="Kerberos",
            algorithm_branch=CLIENT_BRANCH,
            input_field="cname",
            input_value=input_value,
            detected_format=f"{type_name}/servicePrincipalName",
            trace=trace,
        )
    value = components[0]
    downlevel = split_downlevel(value)
    if downlevel is not None:
        domain, account = downlevel
        domain_context = repository.domain_fqdn_for_context(domain)
        for fmt, account_value in [
            (f"{type_name}/downLevelLogonName", account),
            (f"{type_name}/downLevelLogonName+$", f"{account}$"),
        ]:
            result = _match_sam("Kerberos", CLIENT_BRANCH, "cname", input_value, fmt, account_value, domain_context, repository, trace)
            if result is not None:
                return result
        return not_found_result(
            protocol="Kerberos",
            algorithm_branch=CLIENT_BRANCH,
            input_field="cname",
            input_value=input_value,
            detected_format=f"{type_name}/downLevelLogonName",
            unimplemented_steps=["CrackNames"],
            trace=trace,
        )
    parts = split_upn(value)
    if parts is not None:
        account, suffix = parts
        matches = repository.find_generated_upn(account, suffix, realm)
        trace.append({"branch": CLIENT_BRANCH, "step": f"{type_name}/generatedUPN", "syntax_match": True, "lookup_field": "sAMAccountName+domainFQDN", "lookup_value": value, "matched_count": len(matches)})
        result = _resolve_matches("Kerberos", CLIENT_BRANCH, "cname", input_value, f"{type_name}/generatedUPN", "sAMAccountName+domainFQDN", value, matches, trace)
        if result is not None:
            return result
        return not_found_result(
            protocol="Kerberos",
            algorithm_branch=CLIENT_BRANCH,
            input_field="cname",
            input_value=input_value,
            detected_format=f"{type_name}/generatedUPN",
            unimplemented_steps=["CrackNames"],
            trace=trace,
        )
    for fmt, account in [
        (f"{type_name}/sAMAccountName", value),
        (f"{type_name}/sAMAccountName+$", f"{value}$"),
    ]:
        result = _match_sam("Kerberos", CLIENT_BRANCH, "cname", input_value, fmt, account, realm, repository, trace)
        if result is not None:
            return result
    return not_found_result(
        protocol="Kerberos",
        algorithm_branch=CLIENT_BRANCH,
        input_field="cname",
        input_value=input_value,
        detected_format=f"{type_name}/sAMAccountName",
        unimplemented_steps=["CrackNames"],
        trace=trace,
    )


def _resolve_as_x500_principal(
    components: list[str],
    realm: str | None,
    repository: ADSnapshotRepository,
    trace: list[dict],
) -> ResolutionResult:
    input_value = _principal_to_string(components)
    if len(components) != 1:
        return unsupported_result(protocol="Kerberos", algorithm_branch=CLIENT_BRANCH, input_field="cname", input_value=input_value, reason="unsupported_principal_shape", trace=trace)
    value = components[0]
    result = _match_distinguished_name("Kerberos", CLIENT_BRANCH, "cname", input_value, "NT-X500-PRINCIPAL", value, repository, trace)
    if result is not None:
        return result
    return not_found_result(
        protocol="Kerberos",
        algorithm_branch=CLIENT_BRANCH,
        input_field="cname",
        input_value=input_value,
        detected_format="NT-X500-PRINCIPAL/distinguishedName" if looks_like_dn(value) else "NT-X500-PRINCIPAL",
        trace=trace,
    )


def _resolve_as_srv_inst(
    components: list[str],
    realm: str | None,
    repository: ADSnapshotRepository,
    trace: list[dict],
) -> ResolutionResult:
    input_value = _principal_to_string(components)
    if len(components) > 1:
        result = _match_spn("Kerberos", CLIENT_BRANCH, "cname", input_value, "NT-SRV-INST/servicePrincipalName", input_value, realm, repository, trace)
        if result is not None:
            return result
        return not_found_result(
            protocol="Kerberos",
            algorithm_branch=CLIENT_BRANCH,
            input_field="cname",
            input_value=input_value,
            detected_format="NT-SRV-INST/servicePrincipalName",
            trace=trace,
        )
    if len(components) == 1:
        for fmt, account in [
            ("NT-SRV-INST/sAMAccountName", components[0]),
            ("NT-SRV-INST/sAMAccountName+$", f"{components[0]}$"),
        ]:
            result = _match_sam("Kerberos", CLIENT_BRANCH, "cname", input_value, fmt, account, realm, repository, trace)
            if result is not None:
                return result
        domain_fqdn = repository.domain_fqdn_for_context(realm)
        if domain_fqdn:
            result = _match_upn_variant("Kerberos", CLIENT_BRANCH, "cname", input_value, "NT-SRV-INST", f"{components[0]}@{domain_fqdn}", repository, realm, trace)
            if result is not None:
                return result
    return not_found_result(
        protocol="Kerberos",
        algorithm_branch=CLIENT_BRANCH,
        input_field="cname",
        input_value=input_value,
        detected_format="NT-SRV-INST/sAMAccountName",
        unimplemented_steps=["CrackNames"],
        trace=trace,
    )


def _resolve_as_account_principal(
    name_type: int,
    components: list[str],
    realm: str | None,
    repository: ADSnapshotRepository,
    trace: list[dict],
) -> ResolutionResult:
    input_value = _principal_to_string(components)
    type_name = NAME_TYPE_NAMES[name_type]
    if len(components) != 1:
        return not_found_result(
            protocol="Kerberos",
            algorithm_branch=CLIENT_BRANCH,
            input_field="cname",
            input_value=input_value,
            detected_format=f"{type_name}/servicePrincipalName",
            trace=trace,
        )
    value = components[0]
    if split_downlevel(value) is not None:
        return not_found_result(
            protocol="Kerberos",
            algorithm_branch=CLIENT_BRANCH,
            input_field="cname",
            input_value=input_value,
            detected_format=f"{type_name}/downLevelLogonName",
            unimplemented_steps=["CrackNames"],
            trace=trace,
        )
    # AS NT-PRINCIPAL: сначала sAMAccountName, затем machine-account вариант
    # с "$", затем UPN-вариант account@realm-domain.
    for fmt, account in [
        (f"{type_name}/sAMAccountName", value),
        (f"{type_name}/sAMAccountName+$", f"{value}$"),
    ]:
        result = _match_sam("Kerberos", CLIENT_BRANCH, "cname", input_value, fmt, account, realm, repository, trace)
        if result is not None:
            return result
    domain_fqdn = repository.domain_fqdn_for_context(realm)
    if domain_fqdn:
        result = _match_upn_variant("Kerberos", CLIENT_BRANCH, "cname", input_value, type_name, f"{value}@{domain_fqdn}", repository, realm, trace)
        if result is not None:
            return result
    return not_found_result(
        protocol="Kerberos",
        algorithm_branch=CLIENT_BRANCH,
        input_field="cname",
        input_value=input_value,
        detected_format=f"{type_name}/sAMAccountName",
        unimplemented_steps=["CrackNames"],
        trace=trace,
    )


def _resolve_server_service_like(
    name_type: int,
    components: list[str],
    realm: str | None,
    repository: ADSnapshotRepository,
    trace: list[dict],
) -> ResolutionResult:
    input_value = _principal_to_string(components)
    type_name = NAME_TYPE_NAMES[name_type]
    if len(components) == 2 and components[0].casefold() == "krbtgt":
        # Special case krbtgt/service-realm: сам объект ищется по account
        # krbtgt, а второй компонент остается service realm из principal.
        result = _match_sam("Kerberos", SERVER_BRANCH, "sname", input_value, f"{type_name}/krbtgt/sAMAccountName", "krbtgt", realm, repository, trace)
        if result is not None:
            return result
    service_string = _principal_to_string(components)
    if len(components) > 1:
        result = _match_spn("Kerberos", SERVER_BRANCH, "sname", input_value, f"{type_name}/servicePrincipalName", service_string, realm, repository, trace)
        if result is not None:
            return result
    if len(components) == 1 and name_type in SERVER_ACCOUNT_NAME_TYPES:
        # Одноэлементный server principal может совпасть с account name,
        # но только если у объекта есть зарегистрированный SPN.
        value = components[0]
        for fmt, account in [(f"{type_name}/sAMAccountName", value), (f"{type_name}/sAMAccountName+$", f"{value}$")]:
            result = _match_sam_with_registered_spn(input_value, fmt, account, realm, repository, trace)
            if result is not None:
                return result
    detected_format = f"{type_name}/sAMAccountName" if len(components) == 1 else f"{type_name}/servicePrincipalName"
    return not_found_result(
        protocol="Kerberos",
        algorithm_branch=SERVER_BRANCH,
        input_field="sname",
        input_value=input_value,
        detected_format=detected_format,
        trace=trace,
    )


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
    result = _match_spn("Kerberos", SERVER_BRANCH, "sname", input_value, "NT-ENTERPRISE/servicePrincipalName", value, realm, repository, trace)
    if result is not None:
        return result
    result = _match_upn_with_registered_spn(input_value, "NT-ENTERPRISE/userPrincipalName", value, realm, repository, trace)
    if result is not None:
        return result
    result = _match_downlevel_with_registered_spn(input_value, "NT-ENTERPRISE/downLevelLogonName", value, repository, trace)
    if result is not None:
        return result
    for fmt, account in [("NT-ENTERPRISE/sAMAccountName", value), ("NT-ENTERPRISE/sAMAccountName+$", f"{value}$")]:
        result = _match_sam_with_registered_spn(input_value, fmt, account, realm, repository, trace)
        if result is not None:
            return result
    if split_upn(value):
        detected_format = "NT-ENTERPRISE/userPrincipalName"
    else:
        detected_format = "NT-ENTERPRISE/servicePrincipalName" if "/" in value else "NT-ENTERPRISE/sAMAccountName"
    return not_found_result(
        protocol="Kerberos",
        algorithm_branch=SERVER_BRANCH,
        input_field="sname",
        input_value=input_value,
        detected_format=detected_format,
        trace=trace,
    )


def _resolve_tgs_ms_principal(
    name_type: int,
    components: list[str],
    realm: str | None,
    repository: ADSnapshotRepository,
    trace: list[dict],
) -> ResolutionResult:
    input_value = _principal_to_string(components)
    type_name = NAME_TYPE_NAMES[name_type]
    if len(components) != 1:
        return not_found_result(
            protocol="Kerberos",
            algorithm_branch=SERVER_BRANCH,
            input_field="sname",
            input_value=input_value,
            detected_format=f"{type_name}/servicePrincipalName",
            trace=trace,
        )
    value = components[0]
    result = _match_upn_with_registered_spn(input_value, f"{type_name}/userPrincipalName", value, realm, repository, trace)
    if result is not None:
        return result
    result = _match_downlevel_with_registered_spn(input_value, f"{type_name}/downLevelLogonName", value, repository, trace)
    if result is not None:
        return result
    for fmt, account in [(f"{type_name}/sAMAccountName", value), (f"{type_name}/sAMAccountName+$", f"{value}$")]:
        result = _match_sam_with_registered_spn(input_value, fmt, account, realm, repository, trace)
        if result is not None:
            return result
    if split_upn(value):
        detected_format = f"{type_name}/userPrincipalName"
    elif split_downlevel(value):
        detected_format = f"{type_name}/downLevelLogonName"
    else:
        detected_format = f"{type_name}/sAMAccountName"
    return not_found_result(
        protocol="Kerberos",
        algorithm_branch=SERVER_BRANCH,
        input_field="sname",
        input_value=input_value,
        detected_format=detected_format,
        trace=trace,
    )


def _resolve_server_account_only(
    name_type: int,
    components: list[str],
    realm: str | None,
    repository: ADSnapshotRepository,
    trace: list[dict],
) -> ResolutionResult:
    input_value = _principal_to_string(components)
    type_name = NAME_TYPE_NAMES[name_type]
    if len(components) != 1:
        return not_found_result(
            protocol="Kerberos",
            algorithm_branch=SERVER_BRANCH,
            input_field="sname",
            input_value=input_value,
            detected_format=f"{type_name}/servicePrincipalName",
            trace=trace,
        )
    value = components[0]
    for fmt, account in [(f"{type_name}/sAMAccountName", value), (f"{type_name}/sAMAccountName+$", f"{value}$")]:
        result = _match_sam_with_registered_spn(input_value, fmt, account, realm, repository, trace)
        if result is not None:
            return result
    return not_found_result(
        protocol="Kerberos",
        algorithm_branch=SERVER_BRANCH,
        input_field="sname",
        input_value=input_value,
        detected_format=f"{type_name}/sAMAccountName",
        trace=trace,
    )


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
    # Generated/implicit UPN проверяется после explicit UPN. Так сохраняется приоритет AD:
    # явный userPrincipalName выигрывает у generated-формы другого аккаунта, но
    # sAMAccountName@domainFQDN все еще может разрешить аккаунт с отдельным explicit UPN.
    generated_matches = repository.find_generated_upn(account, suffix, domain_context)
    trace.append({"branch": branch, "step": f"{format_prefix}/generatedUPN", "syntax_match": True, "lookup_field": "sAMAccountName+domainFQDN", "lookup_value": value, "matched_count": len(generated_matches)})
    return _resolve_matches(protocol, branch, input_field, input_value, f"{format_prefix}/generatedUPN", "sAMAccountName+domainFQDN", value, generated_matches, trace)


def _match_distinguished_name(
    protocol: str,
    branch: str,
    input_field: str,
    input_value: str,
    format_prefix: str,
    value: str,
    repository: ADSnapshotRepository,
    trace: list[dict],
) -> ResolutionResult | None:
    if not looks_like_dn(value):
        trace.append({"branch": branch, "step": f"{format_prefix}/distinguishedName", "syntax_match": False, "lookup_value": value})
        return None
    matches = repository.find_distinguished_name(value)
    trace.append({"branch": branch, "step": f"{format_prefix}/distinguishedName", "syntax_match": True, "lookup_field": "distinguishedName", "lookup_value": value, "matched_count": len(matches)})
    return _resolve_matches(protocol, branch, input_field, input_value, f"{format_prefix}/distinguishedName", "distinguishedName", value, matches, trace)


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


def _match_sam_with_registered_spn(
    input_value: str,
    matched_format: str,
    account: str,
    domain: str | None,
    repository: ADSnapshotRepository,
    trace: list[dict],
) -> ResolutionResult | None:
    matches = repository.find_sam_in_domain(account, domain)
    trace.append({"branch": SERVER_BRANCH, "step": matched_format, "lookup_field": "sAMAccountName", "lookup_value": account, "matched_count": len(matches)})
    if not matches:
        return None
    spn_ready = [match for match in matches if match.servicePrincipalName]
    trace.append({"branch": SERVER_BRANCH, "step": f"{matched_format}/registered-SPN-check", "lookup_field": "servicePrincipalName", "lookup_value": "any registered SPN on matched account", "matched_count": len(spn_ready)})
    return _resolve_matches("Kerberos", SERVER_BRANCH, "sname", input_value, matched_format, "sAMAccountName", account, spn_ready, trace)


def _match_downlevel_with_registered_spn(
    input_value: str,
    matched_format: str,
    value: str,
    repository: ADSnapshotRepository,
    trace: list[dict],
) -> ResolutionResult | None:
    parts = split_downlevel(value)
    if parts is None:
        trace.append({"branch": SERVER_BRANCH, "step": matched_format, "syntax_match": False, "lookup_value": value})
        return None
    domain, account = parts
    matches = repository.find_downlevel(domain, account)
    trace.append({"branch": SERVER_BRANCH, "step": matched_format, "syntax_match": True, "lookup_field": "domainNetBIOS+sAMAccountName", "lookup_value": value, "matched_count": len(matches)})
    if not matches:
        return None
    spn_ready = [match for match in matches if match.servicePrincipalName]
    trace.append({"branch": SERVER_BRANCH, "step": f"{matched_format}/registered-SPN-check", "lookup_field": "servicePrincipalName", "lookup_value": "any registered SPN on matched account", "matched_count": len(spn_ready)})
    return _resolve_matches("Kerberos", SERVER_BRANCH, "sname", input_value, matched_format, "domainNetBIOS+sAMAccountName", value, spn_ready, trace)


def _match_upn_with_registered_spn(
    input_value: str,
    matched_format: str,
    value: str,
    domain: str | None,
    repository: ADSnapshotRepository,
    trace: list[dict],
) -> ResolutionResult | None:
    if split_upn(value) is None:
        trace.append({"branch": SERVER_BRANCH, "step": matched_format, "syntax_match": False, "lookup_value": value})
        return None
    matches = repository.find_user_principal_name(value, domain)
    trace.append({"branch": SERVER_BRANCH, "step": matched_format, "syntax_match": True, "lookup_field": "userPrincipalName", "lookup_value": value, "matched_count": len(matches)})
    if not matches:
        return None
    spn_ready = [match for match in matches if match.servicePrincipalName]
    trace.append({"branch": SERVER_BRANCH, "step": f"{matched_format}/registered-SPN-check", "lookup_field": "servicePrincipalName", "lookup_value": "any registered SPN on matched account", "matched_count": len(spn_ready)})
    return _resolve_matches("Kerberos", SERVER_BRANCH, "sname", input_value, matched_format, "userPrincipalName", value, spn_ready, trace)


def _match_spn(
    protocol: str,
    branch: str,
    input_field: str,
    input_value: str,
    matched_format: str,
    value: str,
    domain: str | None,
    repository: ADSnapshotRepository,
    trace: list[dict],
) -> ResolutionResult | None:
    # Прямой поиск строки по servicePrincipalName.
    matches = repository.find_service_principal_name(value, domain)
    trace.append({"branch": branch, "step": matched_format, "lookup_field": "servicePrincipalName", "lookup_value": value, "matched_count": len(matches)})
    return _resolve_matches(protocol, branch, input_field, input_value, matched_format, "servicePrincipalName", value, matches, trace)


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


def _is_simple_account_name(value: str) -> bool:
    text = str(value or "").strip()
    if not text or any(separator in text for separator in ("@", "\\", "/")):
        return False
    lowered = text.casefold()
    if lowered.startswith("s-1-") or looks_like_dn(text):
        return False
    if text.startswith("{") and text.endswith("}"):
        return False
    return not any(char.isspace() for char in text)


def _is_krbtgt_principal(components: list[str]) -> bool:
    if not components:
        return False

    normalized = [str(component).casefold() for component in components if component]

    if normalized == ["krbtgt"]:
        return True

    if len(normalized) == 2 and normalized[0] == "krbtgt":
        return True

    if len(normalized) == 1 and normalized[0].startswith("krbtgt/"):
        return True

    return False


def _looks_like_ldap_dn_components(components: list[str]) -> bool:
    if len(components) < 2:
        return False
    dn_prefixes = ("cn=", "ou=", "dc=", "o=", "uid=")
    return all(str(component).strip().casefold().startswith(dn_prefixes) for component in components)
