from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import argparse
import json
import re
import sys
from pathlib import Path
from typing import Callable, Iterable

try:
    import msvcrt
except ImportError:  # pragma: no cover - Windows-only helper is optional.
    msvcrt = None


KRB5_NT_PRINCIPAL = 1
KRB5_NT_SRV_INST = 2
KRB5_NT_ENTERPRISE_PRINCIPAL = 10


class Status(str, Enum):
    FOUND = "found"
    NOT_FOUND = "not_found"
    AMBIGUOUS = "ambiguous"
    UNSUPPORTED = "unsupported"
    INVALID_INPUT = "invalid_input"


@dataclass(frozen=True)
class ADObject:
    sAMAccountName: str
    userPrincipalName: str | None
    distinguishedName: str
    canonicalName: str
    displayName: str
    objectGUID: str
    objectSid: str
    servicePrincipalName: list[str] = field(default_factory=list)
    sIDHistory: list[str] = field(default_factory=list)
    domainFQDN: str = ""
    domainNetBIOS: str = ""
    object_type: str = "user"


@dataclass
class ResolutionResult:
    status: Status
    protocol: str
    input: str
    message: str | None = None
    simulated_traffic_input: dict | None = None
    parsed_format: str | None = None
    parsed_name: str | None = None
    lookup_field: str | None = None
    lookup_value: str | None = None
    name_format: str | None = None
    matched_object: ADObject | None = None
    matched_candidates: list[ADObject] = field(default_factory=list)
    resolved_fields: dict[str, str] = field(default_factory=dict)
    note: str | None = None


@dataclass(frozen=True)
class TestCase:
    section: str
    case_id: str
    protocol: str
    login: str
    expected_status: Status
    expected_name_format: str | None = None
    expected_object: str | None = None
    expected_message: str | None = None
    expected_traffic: dict | None = None
    expected_lookup_field: str | None = None
    snapshot: str = "demo"
    description: str = ""


def norm(value: str | None) -> str:
    return (value or "").strip().casefold()


def split_upn(value: str) -> tuple[str, str] | None:
    if value.count("@") != 1:
        return None
    left, right = value.split("@", 1)
    if not left or not right:
        return None
    return left, right


def split_downlevel(value: str) -> tuple[str, str] | None:
    if "\\" not in value:
        return None
    domain, name = value.split("\\", 1)
    if not domain or not name:
        return None
    return domain, name


def is_guid(value: str) -> bool:
    candidate = value.strip()
    if candidate.startswith("{") and candidate.endswith("}"):
        candidate = candidate[1:-1]
    return bool(
        re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            candidate,
        )
    )


def is_sid(value: str) -> bool:
    return bool(re.fullmatch(r"S-\d-\d+(?:-\d+)+", value.strip(), re.IGNORECASE))


def strip_guid_braces(value: str) -> str:
    value = value.strip()
    if value.startswith("{") and value.endswith("}"):
        return value[1:-1]
    return value


def find_matches(ad_snapshot: Iterable[ADObject], predicate: Callable[[ADObject], bool]) -> list[ADObject]:
    return [obj for obj in ad_snapshot if predicate(obj)]


def field_values(obj: ADObject, field_name: str) -> list[str]:
    if field_name == "generatedUPN":
        return [f"{obj.sAMAccountName}@{obj.domainFQDN}"]
    if field_name == "downLevelLogonName":
        return [f"{obj.domainNetBIOS}\\{obj.sAMAccountName}"]
    if field_name == "servicePrincipalName":
        return list(obj.servicePrincipalName)
    if field_name == "MapSPN":
        return list(obj.servicePrincipalName)
    if field_name == "sIDHistory":
        return list(obj.sIDHistory)
    if field_name == "canonicalNameWithLf" and "/" in obj.canonicalName:
        left, right = obj.canonicalName.rsplit("/", 1)
        return [left + "\n" + right]
    value = getattr(obj, field_name, None)
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def first_matching_field_value(obj: ADObject, field_name: str, lookup_value: str) -> str:
    for value in field_values(obj, field_name):
        if field_name == "objectGUID" and norm(value) == norm(strip_guid_braces(lookup_value)):
            return value
        if norm(value) == norm(lookup_value):
            return value
    return lookup_value


def build_resolved_fields(obj: ADObject, lookup_field: str, lookup_value: str) -> dict[str, str]:
    resolved = {
        "object_type": obj.object_type,
        "sAMAccountName": obj.sAMAccountName,
        "domainFQDN": obj.domainFQDN,
        "domainNetBIOS": obj.domainNetBIOS,
        lookup_field: first_matching_field_value(obj, lookup_field, lookup_value),
    }
    if obj.userPrincipalName:
        resolved["userPrincipalName"] = obj.userPrincipalName
    return resolved


def result_from_matches(
    matches: list[ADObject],
    *,
    protocol: str,
    input_value: str,
    name_format: str,
    message: str | None = None,
    simulated_traffic_input: dict | None = None,
    parsed_format: str | None = None,
    parsed_name: str | None = None,
    lookup_field: str | None = None,
    lookup_value: str | None = None,
) -> ResolutionResult:
    parsed_format = parsed_format or name_format
    parsed_name = parsed_name or input_value
    lookup_field = lookup_field or name_format
    lookup_value = lookup_value or input_value
    if len(matches) == 1:
        return ResolutionResult(
            status=Status.FOUND,
            protocol=protocol,
            message=message,
            input=input_value,
            simulated_traffic_input=simulated_traffic_input,
            parsed_format=parsed_format,
            parsed_name=parsed_name,
            lookup_field=lookup_field,
            lookup_value=lookup_value,
            name_format=name_format,
            matched_object=matches[0],
            resolved_fields=build_resolved_fields(matches[0], lookup_field, lookup_value),
        )
    if len(matches) > 1:
        return ResolutionResult(
            status=Status.AMBIGUOUS,
            protocol=protocol,
            message=message,
            input=input_value,
            simulated_traffic_input=simulated_traffic_input,
            parsed_format=parsed_format,
            parsed_name=parsed_name,
            lookup_field=lookup_field,
            lookup_value=lookup_value,
            name_format=name_format,
            matched_candidates=matches,
            note=f"matched {len(matches)} objects",
        )
    return ResolutionResult(
        status=Status.NOT_FOUND,
        protocol=protocol,
        message=message,
        input=input_value,
        simulated_traffic_input=simulated_traffic_input,
        parsed_format=parsed_format,
        parsed_name=parsed_name,
        lookup_field=lookup_field,
        lookup_value=lookup_value,
        name_format=name_format,
    )


DATA_DIR = Path(__file__).resolve().parent
DATABASE_PATH = DATA_DIR / "ad_database.json"
TEST_CASES_PATH = DATA_DIR / "ad_test_cases.json"
TEST_CONFIG_PATH = DATA_DIR / "ad_test_config.json"


def load_json_file(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(f"Required data file is missing: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: {exc}") from exc


def ad_object_from_dict(data: dict) -> ADObject:
    return ADObject(
        sAMAccountName=data["sAMAccountName"],
        userPrincipalName=data.get("userPrincipalName"),
        distinguishedName=data["distinguishedName"],
        canonicalName=data["canonicalName"],
        displayName=data["displayName"],
        objectGUID=data["objectGUID"],
        objectSid=data["objectSid"],
        servicePrincipalName=list(data.get("servicePrincipalName") or []),
        sIDHistory=list(data.get("sIDHistory") or []),
        domainFQDN=data.get("domainFQDN", ""),
        domainNetBIOS=data.get("domainNetBIOS", ""),
        object_type=data.get("object_type", "user"),
    )


def load_database() -> dict:
    data = load_json_file(DATABASE_PATH)
    demo = [ad_object_from_dict(item) for item in data.get("demo", [])]
    test_extra = [ad_object_from_dict(item) for item in data.get("test_extra", [])]
    return {
        "demo": demo,
        "test": demo + test_extra,
    }


def build_demo_ad_snapshot() -> list[ADObject]:
    return load_database()["demo"]


def build_test_ad_snapshot() -> list[ADObject]:
    return load_database()["test"]


def resolve_explicit_upn(upn: str, ad_snapshot: list[ADObject]) -> list[ADObject]:
    return find_matches(ad_snapshot, lambda obj: norm(obj.userPrincipalName) == norm(upn))


def resolve_generated_upn(upn: str, ad_snapshot: list[ADObject]) -> list[ADObject]:
    parsed = split_upn(upn)
    if not parsed:
        return []
    left, domain = parsed
    return find_matches(
        ad_snapshot,
        lambda obj: norm(obj.sAMAccountName) == norm(left)
        and norm(obj.domainFQDN) == norm(domain),
    )


def resolve_upn_like(upn: str, ad_snapshot: list[ADObject]) -> tuple[list[ADObject], str]:
    explicit = resolve_explicit_upn(upn, ad_snapshot)
    if explicit:
        return explicit, "userPrincipalName"
    generated = resolve_generated_upn(upn, ad_snapshot)
    if generated:
        return generated, "generatedUPN"
    return [], "userPrincipalName/generatedUPN"


def resolve_spn(spn: str, ad_snapshot: list[ADObject]) -> list[ADObject]:
    return find_matches(
        ad_snapshot,
        lambda obj: any(norm(item) == norm(spn) for item in obj.servicePrincipalName),
    )


def resolve_map_spn(spn: str, ad_snapshot: list[ADObject]) -> list[ADObject]:
    # MapSPN is intentionally simplified for this PoC. HOST/name is treated as
    # equivalent to direct SPN lookup and can be extended later with AD mappings.
    return resolve_spn(spn, ad_snapshot)


def resolve_ldap(login: str, ad_snapshot: list[ADObject]) -> ResolutionResult:
    login = login.strip()
    if not login:
        return ResolutionResult(Status.INVALID_INPUT, "LDAP", login, note="empty input")

    checks: list[tuple[str, Callable[[], list[ADObject]]]] = [
        (
            "distinguishedName",
            lambda: find_matches(ad_snapshot, lambda obj: norm(obj.distinguishedName) == norm(login)),
        ),
        ("userPrincipalName", lambda: resolve_explicit_upn(login, ad_snapshot)),
        ("generatedUPN", lambda: resolve_generated_upn(login, ad_snapshot)),
        (
            "downLevelLogonName",
            lambda: find_matches(
                ad_snapshot,
                lambda obj: (parts := split_downlevel(login)) is not None
                and norm(obj.domainNetBIOS) == norm(parts[0])
                and norm(obj.sAMAccountName) == norm(parts[1]),
            ),
        ),
        ("canonicalName", lambda: find_matches(ad_snapshot, lambda obj: norm(obj.canonicalName) == norm(login))),
        (
            "objectGUID",
            lambda: find_matches(
                ad_snapshot,
                lambda obj: is_guid(login) and norm(obj.objectGUID) == norm(strip_guid_braces(login)),
            ),
        ),
        ("displayName", lambda: find_matches(ad_snapshot, lambda obj: norm(obj.displayName) == norm(login))),
        ("servicePrincipalName", lambda: resolve_spn(login, ad_snapshot)),
        ("MapSPN", lambda: resolve_map_spn(login, ad_snapshot)),
        (
            "objectSid",
            lambda: find_matches(
                ad_snapshot,
                lambda obj: is_sid(login) and norm(obj.objectSid) == norm(login),
            ),
        ),
        (
            "sIDHistory",
            lambda: find_matches(
                ad_snapshot,
                lambda obj: is_sid(login) and any(norm(item) == norm(login) for item in obj.sIDHistory),
            ),
        ),
        (
            "canonicalNameWithLf",
            lambda: find_matches(
                ad_snapshot,
                lambda obj: norm(obj.canonicalName.rsplit("/", 1)[0] + "\n" + obj.canonicalName.rsplit("/", 1)[1])
                == norm(login)
                if "/" in obj.canonicalName
                else False,
            ),
        ),
    ]

    for name_format, matcher in checks:
        matches = matcher()
        if matches:
            return result_from_matches(
                matches,
                protocol="LDAP",
                input_value=login,
                name_format=name_format,
            )

    return ResolutionResult(Status.NOT_FOUND, "LDAP", login)


def find_domain_fqdn_by_netbios(netbios: str, ad_snapshot: list[ADObject]) -> str | None:
    for obj in ad_snapshot:
        if norm(obj.domainNetBIOS) == norm(netbios):
            return obj.domainFQDN
    return None


def infer_domain_from_host(host: str, ad_snapshot: list[ADObject]) -> str | None:
    host_norm = norm(host)
    for obj in ad_snapshot:
        domain = obj.domainFQDN
        if domain and (host_norm == norm(domain) or host_norm.endswith("." + norm(domain))):
            return domain
    return None


def simulate_kerberos_from_login(login: str, ad_snapshot: list[ADObject]) -> ResolutionResult | dict:
    login = login.strip()
    if not login:
        return ResolutionResult(Status.INVALID_INPUT, "Kerberos", login, note="empty input")

    if split_upn(login):
        _, domain = split_upn(login) or ("", "")
        return {
            "message": "AS-REQ",
            "field_prefix": "cname",
            "name_type": KRB5_NT_ENTERPRISE_PRINCIPAL,
            "name_string": [login],
            "realm": domain.upper(),
        }

    if (parts := split_downlevel(login)) is not None:
        netbios, name = parts
        domain_fqdn = find_domain_fqdn_by_netbios(netbios, ad_snapshot)
        if not domain_fqdn:
            return ResolutionResult(
                Status.NOT_FOUND,
                "Kerberos",
                login,
                note=f"unknown NetBIOS domain: {netbios}",
            )
        return {
            "message": "AS-REQ",
            "field_prefix": "cname",
            "name_type": KRB5_NT_PRINCIPAL,
            "name_string": [name],
            "realm": domain_fqdn.upper(),
        }

    if "/" in login:
        service, host = login.split("/", 1)
        if not service or not host:
            return ResolutionResult(Status.INVALID_INPUT, "Kerberos", login, note="invalid service principal")
        domain_fqdn = infer_domain_from_host(host, ad_snapshot)
        return {
            "message": "TGS-REQ",
            "field_prefix": "sname",
            "name_type": KRB5_NT_SRV_INST,
            "name_string": [service, host],
            "realm": domain_fqdn.upper() if domain_fqdn else "",
        }

    return ResolutionResult(
        Status.UNSUPPORTED,
        "Kerberos",
        login,
        note="simple Kerberos user input is intentionally unsupported by this PoC",
    )


def kerberos_traffic_dict(simulated: dict) -> dict:
    prefix = simulated["field_prefix"]
    return {
        "message": simulated["message"],
        f"{prefix}.name-type": simulated["name_type"],
        f"{prefix}.name-string[]": simulated["name_string"],
        "realm": simulated["realm"],
    }


def resolve_kerberos(login: str, ad_snapshot: list[ADObject]) -> ResolutionResult:
    simulated = simulate_kerberos_from_login(login, ad_snapshot)
    if isinstance(simulated, ResolutionResult):
        return simulated
    if simulated["message"] == "AS-REQ":
        return resolve_kerberos_as_req(login, simulated, ad_snapshot)
    if simulated["message"] == "TGS-REQ":
        return resolve_kerberos_tgs_req(login, simulated, ad_snapshot)
    return ResolutionResult(Status.UNSUPPORTED, "Kerberos", login, note="unsupported Kerberos message")


def domain_from_realm(realm: str) -> str:
    return realm.lower()


def resolve_kerberos_as_req(login: str, simulated: dict, ad_snapshot: list[ADObject]) -> ResolutionResult:
    name_type = simulated["name_type"]
    name_string = simulated["name_string"]
    realm_domain = domain_from_realm(simulated["realm"])
    traffic = kerberos_traffic_dict(simulated)

    if name_type == KRB5_NT_ENTERPRISE_PRINCIPAL:
        upn = name_string[0]
        matches = resolve_explicit_upn(upn, ad_snapshot)
        if matches:
            return result_from_matches(
                matches,
                protocol="Kerberos",
                message="AS-REQ",
                input_value=login,
                simulated_traffic_input=traffic,
                name_format="NT-ENTERPRISE/userPrincipalName",
                parsed_format="NT-ENTERPRISE",
                parsed_name=upn,
                lookup_field="userPrincipalName",
                lookup_value=upn,
            )

        matches = resolve_generated_upn(upn, ad_snapshot)
        if matches:
            return result_from_matches(
                matches,
                protocol="Kerberos",
                message="AS-REQ",
                input_value=login,
                simulated_traffic_input=traffic,
                name_format="NT-ENTERPRISE/generatedUPN",
                parsed_format="NT-ENTERPRISE",
                parsed_name=upn,
                lookup_field="generatedUPN",
                lookup_value=upn,
            )

        parsed = split_upn(upn)
        if parsed:
            left, domain = parsed
            if norm(domain) == norm(realm_domain):
                matches = find_matches(
                    ad_snapshot,
                    lambda obj: norm(obj.domainFQDN) == norm(realm_domain)
                    and norm(obj.sAMAccountName) == norm(left),
                )
                if matches:
                    return result_from_matches(
                        matches,
                        protocol="Kerberos",
                        message="AS-REQ",
                        input_value=login,
                        simulated_traffic_input=traffic,
                        name_format="NT-ENTERPRISE/sAMAccountName",
                        parsed_format="NT-ENTERPRISE",
                        parsed_name=upn,
                        lookup_field="sAMAccountName",
                        lookup_value=left,
                    )

                matches = find_matches(
                    ad_snapshot,
                    lambda obj: norm(obj.domainFQDN) == norm(realm_domain)
                    and norm(obj.sAMAccountName) == norm(left + "$"),
                )
                if matches:
                    return result_from_matches(
                        matches,
                        protocol="Kerberos",
                        message="AS-REQ",
                        input_value=login,
                        simulated_traffic_input=traffic,
                        name_format="NT-ENTERPRISE/sAMAccountName+$",
                        parsed_format="NT-ENTERPRISE",
                        parsed_name=upn,
                        lookup_field="sAMAccountName",
                        lookup_value=left + "$",
                    )

        # CrackNames is deliberately left as a future extension point.
        return ResolutionResult(
            Status.NOT_FOUND,
            "Kerberos",
            login,
            message="AS-REQ",
            simulated_traffic_input=traffic,
        )

    if name_type == KRB5_NT_PRINCIPAL:
        if len(name_string) != 1:
            return ResolutionResult(
                Status.UNSUPPORTED,
                "Kerberos",
                login,
                message="AS-REQ",
                simulated_traffic_input=traffic,
                note="multi-component NT-PRINCIPAL is not implemented in this PoC",
            )

        name = name_string[0]
        matches = find_matches(
            ad_snapshot,
            lambda obj: norm(obj.domainFQDN) == norm(realm_domain)
            and norm(obj.sAMAccountName) == norm(name),
        )
        if matches:
            return result_from_matches(
                matches,
                protocol="Kerberos",
                message="AS-REQ",
                input_value=login,
                simulated_traffic_input=traffic,
                name_format="NT-PRINCIPAL/sAMAccountName",
                parsed_format="NT-PRINCIPAL",
                parsed_name=name,
                lookup_field="sAMAccountName",
                lookup_value=name,
            )

        matches = find_matches(
            ad_snapshot,
            lambda obj: norm(obj.domainFQDN) == norm(realm_domain)
            and norm(obj.sAMAccountName) == norm(name + "$"),
        )
        if matches:
            return result_from_matches(
                matches,
                protocol="Kerberos",
                message="AS-REQ",
                input_value=login,
                simulated_traffic_input=traffic,
                name_format="NT-PRINCIPAL/sAMAccountName+$",
                parsed_format="NT-PRINCIPAL",
                parsed_name=name,
                lookup_field="sAMAccountName",
                lookup_value=name + "$",
            )

        upn = f"{name}@{realm_domain}"
        matches, upn_format = resolve_upn_like(upn, ad_snapshot)
        if matches:
            return result_from_matches(
                matches,
                protocol="Kerberos",
                message="AS-REQ",
                input_value=login,
                simulated_traffic_input=traffic,
                name_format=f"NT-PRINCIPAL/{upn_format}",
                parsed_format="NT-PRINCIPAL",
                parsed_name=name,
                lookup_field=upn_format,
                lookup_value=upn,
            )

        # CrackNames is deliberately left as a future extension point.
        return ResolutionResult(
            Status.NOT_FOUND,
            "Kerberos",
            login,
            message="AS-REQ",
            simulated_traffic_input=traffic,
        )

    return ResolutionResult(
        Status.UNSUPPORTED,
        "Kerberos",
        login,
        message="AS-REQ",
        simulated_traffic_input=traffic,
        note=f"unsupported cname.name-type: {name_type}",
    )


def resolve_kerberos_tgs_req(login: str, simulated: dict, ad_snapshot: list[ADObject]) -> ResolutionResult:
    name_type = simulated["name_type"]
    name_string = simulated["name_string"]
    realm_domain = domain_from_realm(simulated["realm"])
    traffic = kerberos_traffic_dict(simulated)

    if name_type != KRB5_NT_SRV_INST:
        return ResolutionResult(
            Status.UNSUPPORTED,
            "Kerberos",
            login,
            message="TGS-REQ",
            simulated_traffic_input=traffic,
            note=f"unsupported sname.name-type: {name_type}",
        )

    service_principal = "/".join(name_string)
    matches = resolve_spn(service_principal, ad_snapshot)
    if matches:
        return result_from_matches(
            matches,
            protocol="Kerberos",
            message="TGS-REQ",
            input_value=login,
            simulated_traffic_input=traffic,
            name_format="NT-SRV-INST/servicePrincipalName",
            parsed_format="NT-SRV-INST",
            parsed_name=service_principal,
            lookup_field="servicePrincipalName",
            lookup_value=service_principal,
        )

    if len(name_string) == 1:
        name = name_string[0]
        matches = find_matches(
            ad_snapshot,
            lambda obj: norm(obj.domainFQDN) == norm(realm_domain)
            and norm(obj.sAMAccountName) == norm(name),
        )
        if matches:
            return result_from_matches(
                matches,
                protocol="Kerberos",
                message="TGS-REQ",
                input_value=login,
                simulated_traffic_input=traffic,
                name_format="NT-SRV-INST/sAMAccountName",
                parsed_format="NT-SRV-INST",
                parsed_name="/".join(name_string),
                lookup_field="sAMAccountName",
                lookup_value=name,
            )

        matches = find_matches(
            ad_snapshot,
            lambda obj: norm(obj.domainFQDN) == norm(realm_domain)
            and norm(obj.sAMAccountName) == norm(name + "$"),
        )
        if matches:
            return result_from_matches(
                matches,
                protocol="Kerberos",
                message="TGS-REQ",
                input_value=login,
                simulated_traffic_input=traffic,
                name_format="NT-SRV-INST/sAMAccountName+$",
                parsed_format="NT-SRV-INST",
                parsed_name="/".join(name_string),
                lookup_field="sAMAccountName",
                lookup_value=name + "$",
            )

    return ResolutionResult(
        Status.NOT_FOUND,
        "Kerberos",
        login,
        message="TGS-REQ",
        simulated_traffic_input=traffic,
    )


def object_label(obj: ADObject) -> str:
    return obj.sAMAccountName


def print_dict_block(title: str, data: dict) -> None:
    print(f"{title} = {{")
    for key, value in data.items():
        print(f"  {key} = {value}")
    print("}")


def format_dict_block(title: str, data: dict) -> list[str]:
    lines = [f"{title} = {{"]
    for key, value in data.items():
        lines.append(f"  {key} = {value}")
    lines.append("}")
    return lines


def concise_result_line(result: ResolutionResult) -> str:
    obj = result.matched_object.sAMAccountName if result.matched_object else "-"
    details = [
        f"status={result.status.value}",
        f"protocol={result.protocol}",
    ]
    if result.message:
        details.append(f"message={result.message}")
    if result.name_format:
        details.append(f"format={result.name_format}")
    if result.lookup_field:
        details.append(f"lookup={result.lookup_field}:{result.lookup_value}")
    if result.matched_object:
        label = "service" if result.protocol == "Kerberos" and result.message == "TGS-REQ" else "user"
        details.append(f"{label}={obj}")
    if result.matched_candidates:
        details.append("candidates=" + ",".join(obj.sAMAccountName for obj in result.matched_candidates))
    if result.note:
        details.append(f"note={result.note}")
    return ", ".join(details)


def format_result_lines(result: ResolutionResult) -> list[str]:
    lines = [
        f"status = {result.status.value}",
        f"protocol = {result.protocol}",
    ]
    if result.message:
        lines.append(f"message = {result.message}")
    lines.append(f"input = {result.input}")
    if result.simulated_traffic_input:
        lines.extend(format_dict_block("simulated_traffic_input", result.simulated_traffic_input))
    if result.name_format:
        lines.append(f"name_format = {result.name_format}")
    if result.parsed_format or result.parsed_name:
        lines.extend(
            format_dict_block(
                "parsed_input",
                {
                    "format": result.parsed_format or "",
                    "name": result.parsed_name or "",
                },
            )
        )
    if result.lookup_field or result.lookup_value:
        lines.extend(
            format_dict_block(
                "ad_lookup",
                {
                    "field": result.lookup_field or "",
                    "value": result.lookup_value or "",
                },
            )
        )
    if result.matched_object:
        if result.protocol == "Kerberos" and result.message == "TGS-REQ":
            lines.append(f"matched_service = {object_label(result.matched_object)}")
        else:
            lines.append(f"matched_user = {object_label(result.matched_object)}")
        lines.append(f"matched_object_type = {result.matched_object.object_type}")
        lines.append(f"matched_domain = {result.matched_object.domainFQDN}")
    if result.resolved_fields:
        lines.extend(format_dict_block("resolved_fields", result.resolved_fields))
    if result.matched_candidates:
        lines.append("matched_candidates = [")
        for obj in result.matched_candidates:
            matched_value = first_matching_field_value(
                obj,
                result.lookup_field or result.name_format or "",
                result.lookup_value or result.input,
            )
            lines.append(
                f"  {obj.sAMAccountName} "
                f"(object_type={obj.object_type}, domain={obj.domainFQDN}, "
                f"{result.lookup_field}={matched_value})"
            )
        lines.append("]")
    if result.note:
        lines.append(f"note = {result.note}")
    return lines


def print_result(result: ResolutionResult) -> None:
    print()
    print("Результат:")
    for line in format_result_lines(result):
        print(line)


def print_choices_help(choices: list[str]) -> None:
    print("Варианты:")
    for choice in choices:
        print(f"  {choice}")
    print("Подсказка: нажмите Tab для автодополнения, Enter для выбора.")


def complete_value(current: str, choices: list[str], tab_index: int) -> tuple[str, int]:
    matches = [choice for choice in choices if choice.casefold().startswith(current.casefold())]
    if not matches:
        return current, 0
    next_value = matches[tab_index % len(matches)]
    return next_value, tab_index + 1


def read_with_tab_windows(prompt: str, choices: list[str], default: str | None = None) -> str:
    assert msvcrt is not None
    buffer = default or ""
    tab_index = 0
    print(prompt, end="", flush=True)
    if buffer:
        print(buffer, end="", flush=True)

    while True:
        char = msvcrt.getwch()
        if char in ("\r", "\n"):
            print()
            return buffer.strip()
        if char == "\x03":
            raise KeyboardInterrupt
        if char == "\b":
            if buffer:
                buffer = buffer[:-1]
                tab_index = 0
                print("\b \b", end="", flush=True)
            continue
        if char == "\t":
            buffer, tab_index = complete_value(buffer, choices, tab_index)
            print("\r" + " " * (len(prompt) + 120), end="")
            print("\r" + prompt + buffer, end="", flush=True)
            continue
        if char in ("\x00", "\xe0"):
            # Ignore arrows/function keys; they arrive as two-character sequences.
            msvcrt.getwch()
            continue
        buffer += char
        tab_index = 0
        print(char, end="", flush=True)


def read_with_tab_readline(prompt: str, choices: list[str], default: str | None = None) -> str:
    import readline

    def completer(text: str, state: int) -> str | None:
        matches = [choice for choice in choices if choice.casefold().startswith(text.casefold())]
        if state < len(matches):
            return matches[state]
        return None

    old_completer = readline.get_completer()
    readline.set_completer(completer)
    readline.parse_and_bind("tab: complete")
    try:
        if default:
            readline.set_startup_hook(lambda: readline.insert_text(default))
        value = input(prompt)
    finally:
        readline.set_startup_hook(None)
        readline.set_completer(old_completer)
    return value.strip()


def read_with_tab(prompt: str, choices: list[str], default: str | None = None) -> str:
    if not sys.stdin.isatty():
        value = input(prompt)
        return value.strip() or (default or "")
    if msvcrt is not None:
        return read_with_tab_windows(prompt, choices, default)
    try:
        return read_with_tab_readline(prompt, choices, default)
    except Exception:
        value = input(prompt)
        return value.strip() or (default or "")


def ask_choice(prompt: str, choices: list[str], *, default: str | None = None, allow_empty: bool = False) -> str:
    while True:
        value = read_with_tab(prompt, choices, default).strip()
        if not value and allow_empty:
            return value
        if not value and default:
            return default
        matches = [choice for choice in choices if choice.casefold() == value.casefold()]
        if matches:
            return matches[0]
        print(f"Неизвестный вариант: {value!r}")
        print_choices_help(choices)


def login_suggestions(protocol: str) -> list[str]:
    cases = build_test_cases()
    return sorted({case.login for case in cases if case.protocol == protocol and case.login})


def test_case_from_dict(data: dict) -> TestCase:
    return TestCase(
        section=data["section"],
        case_id=data["case_id"],
        protocol=data["protocol"],
        login=data.get("login", ""),
        expected_status=Status(data["expected_status"]),
        expected_name_format=data.get("expected_name_format"),
        expected_object=data.get("expected_object"),
        expected_message=data.get("expected_message"),
        expected_traffic=data.get("expected_traffic"),
        expected_lookup_field=data.get("expected_lookup_field"),
        snapshot=data.get("snapshot", "demo"),
        description=data.get("description", ""),
    )


def build_test_cases() -> list[TestCase]:
    data = load_json_file(TEST_CASES_PATH)
    if not isinstance(data, list):
        raise SystemExit(f"Expected a JSON list in {TEST_CASES_PATH}")
    return [test_case_from_dict(item) for item in data]
def resolve_for_test(case: TestCase) -> ResolutionResult:
    snapshot = build_test_ad_snapshot() if case.snapshot == "test" else build_demo_ad_snapshot()
    if case.protocol == "ldap":
        return resolve_ldap(case.login, snapshot)
    if case.protocol == "kerberos":
        return resolve_kerberos(case.login, snapshot)
    return ResolutionResult(Status.INVALID_INPUT, case.protocol.upper(), case.login)


def check_test_case(case: TestCase, result: ResolutionResult) -> list[str]:
    errors: list[str] = []
    if result.status != case.expected_status:
        errors.append(f"status expected {case.expected_status.value}, got {result.status.value}")
    if case.expected_name_format and result.name_format != case.expected_name_format:
        errors.append(f"name_format expected {case.expected_name_format}, got {result.name_format}")
    if case.expected_object:
        actual_object = result.matched_object.sAMAccountName if result.matched_object else None
        if actual_object != case.expected_object:
            errors.append(f"object expected {case.expected_object}, got {actual_object}")
    if case.expected_lookup_field and result.lookup_field != case.expected_lookup_field:
        errors.append(f"lookup_field expected {case.expected_lookup_field}, got {result.lookup_field}")
    if case.expected_message and result.message != case.expected_message:
        errors.append(f"message expected {case.expected_message}, got {result.message}")
    if case.expected_traffic:
        traffic = result.simulated_traffic_input or {}
        for key, expected_value in case.expected_traffic.items():
            actual_value = traffic.get(key)
            if actual_value != expected_value:
                errors.append(f"traffic {key} expected {expected_value}, got {actual_value}")
    return errors


def list_test_sections() -> None:
    sections = sorted({case.section for case in build_test_cases()})
    print("Available test sections:")
    for section in sections:
        print(f"  {section}")
    print()
    print("Available test groups:")
    for group in sorted(TEST_GROUPS):
        print(f"  {group}")


def load_test_config() -> dict:
    data = load_json_file(TEST_CONFIG_PATH)
    groups = {}
    for name, sections in data.get("groups", {}).items():
        groups[name] = None if sections is None else set(sections)
    return {
        "groups": groups,
        "section_descriptions": data.get("section_descriptions", {}),
    }


TEST_CONFIG = load_test_config()
TEST_GROUPS = TEST_CONFIG["groups"]
SECTION_DESCRIPTIONS = TEST_CONFIG["section_descriptions"]


def case_description(case: TestCase) -> str:
    if case.description:
        return case.description
    return (
        f"{case.protocol.upper()} input {case.login!r}: ожидается "
        f"status={case.expected_status.value}"
        + (f", name_format={case.expected_name_format}" if case.expected_name_format else "")
        + (f", object={case.expected_object}" if case.expected_object else "")
        + "."
    )


def expected_summary(case: TestCase) -> str:
    parts = [f"status={case.expected_status.value}"]
    if case.expected_message:
        parts.append(f"message={case.expected_message}")
    if case.expected_name_format:
        parts.append(f"name_format={case.expected_name_format}")
    if case.expected_object:
        parts.append(f"object={case.expected_object}")
    if case.expected_lookup_field:
        parts.append(f"lookup_field={case.expected_lookup_field}")
    if case.expected_traffic:
        traffic = ", ".join(f"{key}={value}" for key, value in case.expected_traffic.items())
        parts.append(f"traffic[{traffic}]")
    return ", ".join(parts)


def filter_test_cases(cases: list[TestCase], section_filter: str | None, group_filter: str | None) -> list[TestCase]:
    if group_filter:
        group = TEST_GROUPS.get(group_filter)
        if group is None and group_filter != "all":
            return []
        if group is not None:
            cases = [case for case in cases if case.section in group]
    if section_filter:
        cases = [case for case in cases if case.section == section_filter]
    return cases


def print_case_report(case: TestCase, result: ResolutionResult, errors: list[str]) -> None:
    print(f"{case.case_id}: {case.protocol} {case.login!r}")
    print(f"Описание: {case_description(case)}")
    print(f"Ожидание: {expected_summary(case)}")
    print("Фактический разбор:")
    for line in format_result_lines(result):
        print(f"  {line}")
    if errors:
        print("Итог: FAIL")
        for error in errors:
            print(f"  - {error}")
    else:
        print("Итог: PASS")
    print()


def print_case_simple(case: TestCase, result: ResolutionResult, errors: list[str]) -> None:
    verdict = "FAIL" if errors else "PASS"
    print(f"{verdict} {case.case_id}: {case_description(case)}")
    print(f"  input: {case.protocol} {case.login!r}")
    print(f"  result: {concise_result_line(result)}")
    if errors:
        for error in errors:
            print(f"  - {error}")
    print()


def run_case_player(cases: list[TestCase], *, detailed: bool) -> int:
    current_section = None
    passed = 0
    failed = 0

    for case in cases:
        if case.section != current_section:
            current_section = case.section
            print()
            print(f"== {current_section} ==")
            print(SECTION_DESCRIPTIONS.get(current_section, ""))
            print()

        result = resolve_for_test(case)
        errors = check_test_case(case, result)
        if detailed:
            print_case_report(case, result, errors)
        else:
            print_case_simple(case, result, errors)

        if errors:
            failed += 1
        else:
            passed += 1

    print(f"Summary: passed={passed}, failed={failed}, total={passed + failed}")
    return 0 if failed == 0 else 1


def run_tests(
    section_filter: str | None = None,
    group_filter: str | None = None,
    verbose: bool = False,
    report: bool = False,
) -> int:
    cases = build_test_cases()
    cases = filter_test_cases(cases, section_filter, group_filter)
    if not cases:
        print("No tests found for the requested filters.")
        return 1

    current_section = None
    passed = 0
    failed = 0

    for case in cases:
        if case.section != current_section:
            current_section = case.section
            print()
            print(f"== {current_section} ==")
            if report:
                print(SECTION_DESCRIPTIONS.get(current_section, ""))
                print()

        result = resolve_for_test(case)
        errors = check_test_case(case, result)
        if report:
            print_case_report(case, result, errors)
            if errors:
                failed += 1
            else:
                passed += 1
            continue

        if errors:
            failed += 1
            print(f"FAIL {case.case_id}: {case.protocol} {case.login!r}")
            for error in errors:
                print(f"  - {error}")
            print(
                "  actual: "
                f"status={result.status.value}, "
                f"name_format={result.name_format}, "
                f"object={result.matched_object.sAMAccountName if result.matched_object else None}, "
                f"message={result.message}"
            )
        else:
            passed += 1
            if verbose:
                print(f"PASS {case.case_id}: {case.protocol} {case.login!r}")

    print()
    print(f"Summary: passed={passed}, failed={failed}, total={passed + failed}")
    return 0 if failed == 0 else 1


def select_auto_cases() -> tuple[list[TestCase], str]:
    cases = build_test_cases()
    sections = sorted({case.section for case in cases})
    group_choices = ["all", "ordinary", "corner", "negative", "edge"]
    choices = list(dict.fromkeys(group_choices + sections + ["back"]))

    print()
    print("Автоматический режим")
    print("Можно выбрать группу или конкретный раздел.")
    print_choices_help(choices)
    selected = ask_choice("Что проиграть: ", choices)

    if selected == "back":
        return [], selected
    if selected in TEST_GROUPS:
        selected_cases = filter_test_cases(cases, None, selected)
    else:
        selected_cases = filter_test_cases(cases, selected, None)
    return selected_cases, selected


def run_auto_interactive() -> None:
    selected_cases, selected_name = select_auto_cases()
    if not selected_cases:
        return

    output_choices = ["detailed", "simple", "back"]
    print()
    print("Формат вывода:")
    print("  detailed - описание кейса, ожидание и полный фактический разбор")
    print("  simple   - описание кейса и краткий фактический результат")
    print_choices_help(output_choices)
    output_mode = ask_choice("Как показать результат: ", output_choices, default="detailed")
    if output_mode == "back":
        return

    print()
    print(f"Запускаю: {selected_name}, вывод: {output_mode}")
    run_case_player(selected_cases, detailed=output_mode == "detailed")


def run_manual_interactive() -> None:
    ad_snapshot = build_test_ad_snapshot()
    protocol_choices = ["ldap", "kerberos", "back"]

    while True:
        print()
        print("Ручной режим")
        print("Используется расширенная тестовая AD-база с обычными объектами и corner-case объектами.")
        print_choices_help(protocol_choices)
        protocol = ask_choice("Введите протокол: ", protocol_choices)
        if protocol == "back":
            return

        suggestions = login_suggestions(protocol)
        print()
        print("Введите логин / имя. Можно нажимать Tab, чтобы подставлять примеры из тестовых кейсов.")
        if suggestions:
            print("Примеры:")
            for item in suggestions[:12]:
                print(f"  {item}")
            if len(suggestions) > 12:
                print(f"  ... ещё {len(suggestions) - 12}")
        login = read_with_tab("Введите логин / имя: ", suggestions)

        if protocol == "ldap":
            result = resolve_ldap(login, ad_snapshot)
        elif protocol == "kerberos":
            result = resolve_kerberos(login, ad_snapshot)
        else:
            result = ResolutionResult(
                Status.INVALID_INPUT,
                protocol.upper() if protocol else "UNKNOWN",
                login,
                note="protocol must be ldap or kerberos",
            )

        print_result(result)
        print()

        again = ask_choice("Проверить ещё одно имя? [yes/no]: ", ["yes", "no"], default="no")
        if again == "no":
            break


def print_ad_database(ad_snapshot: list[ADObject]) -> None:
    print()
    print(f"AD database snapshot: {len(ad_snapshot)} objects")
    for obj in ad_snapshot:
        print()
        print(f"- {obj.sAMAccountName} ({obj.object_type})")
        print(f"  domainFQDN = {obj.domainFQDN}")
        print(f"  domainNetBIOS = {obj.domainNetBIOS}")
        print(f"  userPrincipalName = {obj.userPrincipalName or ''}")
        print(f"  generatedUPN = {obj.sAMAccountName}@{obj.domainFQDN}")
        print(f"  downLevelLogonName = {obj.domainNetBIOS}\\{obj.sAMAccountName}")
        print(f"  distinguishedName = {obj.distinguishedName}")
        print(f"  canonicalName = {obj.canonicalName}")
        print(f"  displayName = {obj.displayName}")
        print(f"  objectGUID = {obj.objectGUID}")
        print(f"  objectSid = {obj.objectSid}")
        print(f"  servicePrincipalName = {obj.servicePrincipalName}")
        print(f"  sIDHistory = {obj.sIDHistory}")


def run_main_menu() -> None:
    print("AD-like Name Resolution PoC")
    print("PoC имитирует вход из LDAP/Kerberos трафика и показывает, как имя разрешается в AD snapshot.")
    print("В меню и полях с примерами работает Tab-автодополнение.")
    print()

    choices = ["manual", "auto", "database", "exit"]
    while True:
        print()
        print("Главное меню")
        print("  manual - вручную ввести protocol + login")
        print("  auto   - проиграть готовые кейсы")
        print("  database - показать AD snapshot")
        print("  exit   - выйти")
        print_choices_help(choices)
        mode = ask_choice("Выберите режим: ", choices)
        if mode == "manual":
            run_manual_interactive()
        elif mode == "auto":
            run_auto_interactive()
        elif mode == "database":
            print_ad_database(build_test_ad_snapshot())
        elif mode == "exit":
            return


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="AD-like name resolution PoC. Default mode is interactive CLI.",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="run built-in checks instead of interactive input",
    )
    parser.add_argument(
        "--test-section",
        help="run only one test section, for example ldap_basic or kerberos_corner",
    )
    parser.add_argument(
        "--test-group",
        choices=sorted(TEST_GROUPS),
        help="run a grouped suite: ordinary/basic, corner, negative, edge, or all",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="print case descriptions and actual resolver output for each test",
    )
    parser.add_argument(
        "--list-tests",
        action="store_true",
        help="show available test sections",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="print passing test cases too",
    )
    args = parser.parse_args(argv)

    if args.list_tests:
        list_test_sections()
        return 0
    if args.test or args.test_section or args.test_group or args.report:
        return run_tests(args.test_section, args.test_group, args.verbose, args.report)

    run_main_menu()
    return 0


if __name__ == "__main__":
    sys.exit(main())


