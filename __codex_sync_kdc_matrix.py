import csv
import io
import json
import re
import zipfile
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parent
TESTS_PATH = ROOT / "tests.json"
SNAPSHOT_PATH = ROOT / "ad_snapshot.json"
README_PATH = ROOT / "README.md"
RESULTS_PATH = ROOT / "kerberos-corner-results-v2.zip"

DOMAIN = "pastukhov.lab"
REALM = "PASTUKHOV.LAB"
NETBIOS = "PASTUKHOV"

NAME_TYPES = {
    "NT_UNKNOWN": 0,
    "NT_PRINCIPAL": 1,
    "NT_SRV_INST": 2,
    "NT_SRV_HST": 3,
    "NT_SRV_XHST": 4,
    "NT_UID": 5,
    "NT_X500_PRINCIPAL": 6,
    "NT_SMTP_NAME": 7,
    "NT_ENTERPRISE": 10,
    "NT_WELLKNOWN": 11,
    "NT_SRV_HST_DOMAIN": 12,
    "NT_MS_PRINCIPAL": -128,
    "NT_MS_PRINCIPAL_AND_ID": -129,
    "NT_ENT_PRINCIPAL_AND_ID": -130,
}

CLIENT_BRANCH = "Client Principal Lookup"
SERVER_BRANCH = "Server Principal Lookup"

COMPACT_KDC_TEST_IDS = {
    # AS-REQ cname: client principal lookup.
    "kdc_as_req_cname_as_cname_canonical_false",
    "kdc_as_req_cname_as_cname_display_false",
    "kdc_as_req_cname_as_cname_dn_false",
    "kdc_as_req_cname_as_cname_dn_kxbase",
    "kdc_as_req_cname_as_cname_dns_backslash_kxbase",
    "kdc_as_req_cname_as_cname_downlevel_kxbase",
    "kdc_as_req_cname_as_cname_implicit_upn_false",
    "kdc_as_req_cname_as_cname_implicit_upn_kximplicit",
    "kdc_as_req_cname_as_cname_machine_no_dollar_dc01",
    "kdc_as_req_cname_as_cname_objectguid_false",
    "kdc_as_req_cname_as_cname_objectsid_false",
    "kdc_as_req_cname_as_cname_sam_base_false",
    "kdc_as_req_cname_as_cname_sam_base_kxbase",
    "kdc_as_req_cname_as_cname_short_upn_false",
    "kdc_as_req_cname_as_cname_short_upn_kxalias",
    "kdc_as_req_cname_as_cname_spn_client_false",
    "kdc_as_req_cname_as_cname_spn_client_kxsvc",
    "kdc_as_req_cname_as_cname_upn_base_false",
    "kdc_as_req_cname_as_cname_upn_base_kxbase",
    "kdc_as_req_cname_as_cname_upn_conflict_false",
    "kdc_as_req_cname_as_cname_upn_conflict_kxconflict",
    "kdc_as_req_cname_as_cname_upn_conflict_kxowner",
    "kdc_as_req_cname_as_cname_upnset_explicit_kxupnset",
    "kdc_as_req_cname_as_cname_upnset_generated_kxupnset",

    # AS-REQ sname: KDC server principal lookup during AS exchange.
    "kdc_as_req_sname_as_sname_host_fqdn_kxsvc",
    "kdc_as_req_sname_as_sname_http_fqdn_lower_false",
    "kdc_as_req_sname_as_sname_http_fqdn_lower_kxsvc",
    "kdc_as_req_sname_as_sname_krbtgt_pastukhov_false",
    "kdc_as_req_sname_as_sname_krbtgt_pastukhov_krbtgt",
    "kdc_as_req_sname_as_sname_krbtgt_sam_krbtgt",
    "kdc_as_req_sname_as_sname_machine_dc01",
    "kdc_as_req_sname_as_sname_svc_sam_false",
    "kdc_as_req_sname_as_sname_svc_sam_kxsvc",

    # TGS-REQ sname: service ticket server principal lookup.
    "kdc_tgs_req_sname_tgs_sname_cifs_dc_fqdn_dc01",
    "kdc_tgs_req_sname_tgs_sname_host_fqdn_kxsvc",
    "kdc_tgs_req_sname_tgs_sname_http_fqdn_lower_false",
    "kdc_tgs_req_sname_tgs_sname_http_fqdn_lower_kxsvc",
    "kdc_tgs_req_sname_tgs_sname_nospn_sam_false",
    "kdc_tgs_req_sname_tgs_sname_nospn_upn_false",
    "kdc_tgs_req_sname_tgs_sname_svc_downlevel_false",
    "kdc_tgs_req_sname_tgs_sname_svc_downlevel_kxsvc",
    "kdc_tgs_req_sname_tgs_sname_svc_sam_false",
    "kdc_tgs_req_sname_tgs_sname_svc_sam_kxsvc",
    "kdc_tgs_req_sname_tgs_sname_svc_upn_false",
    "kdc_tgs_req_sname_tgs_sname_svc_upn_kxsvc",
}

CATEGORY_LABELS = {
    "ldap_table": "LDAP: базовые форматы имени",
    "ldap_algorithm": "LDAP: дополнительные форматы",
    "ldap_dn_special": "LDAP: DN со спецсимволами",
    "ldap_corner": "LDAP: корнеры и приоритет форматов",
    "kerberos_client_lookup": "Kerberos: AS-REQ / Client Principal Lookup",
    "kerberos_server_lookup": "Kerberos: Server Principal Lookup",
}


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def dump_json(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def load_kdc_rows():
    with zipfile.ZipFile(RESULTS_PATH) as archive:
        data = archive.read("full_results.csv").decode("utf-8-sig")
    return list(csv.DictReader(io.StringIO(data)))


def kx_object(
    object_id,
    object_type,
    sam,
    upn,
    display,
    guid_tail,
    sid_rid,
    spns=None,
):
    return {
        "id": object_id,
        "object_type": object_type,
        "sAMAccountName": sam,
        "userPrincipalName": upn,
        "distinguishedName": f"CN={object_id},CN=Users,DC=pastukhov,DC=lab",
        "canonicalName": f"pastukhov.lab/Users/{object_id}",
        "displayName": display,
        "objectGUID": guid_tail,
        "objectSid": f"S-1-5-21-2845156888-2425353457-3474467337-{sid_rid}",
        "servicePrincipalName": spns or [],
        "sIDHistory": [],
        "domainFQDN": DOMAIN,
        "domainNetBIOS": NETBIOS,
    }


def ensure_snapshot_objects(snapshot):
    existing = {obj["id"] for obj in snapshot["objects"]}
    additions = [
        kx_object(
            "kxBase",
            "user",
            "kxBase",
            "kxBase@pastukhov.lab",
            "KX Base",
            "{f0b32a89-9678-4e34-9fa3-b206aeadba3b}",
            "1158",
        ),
        kx_object(
            "kxSvc",
            "user",
            "kxSvc",
            "kxSvc@pastukhov.lab",
            "KX Service",
            "{dddddddd-0000-0000-0000-000000000101}",
            "1159",
            [
                "HTTP/kxspn22",
                "HTTP/kxspn22.pastukhov.lab",
                "HOST/kxspn22",
                "HOST/kxspn22.pastukhov.lab",
            ],
        ),
        kx_object(
            "kxImplicit",
            "user",
            "kxImplicit",
            None,
            "KX Implicit",
            "{dddddddd-0000-0000-0000-000000000102}",
            "1160",
        ),
        kx_object(
            "kxUpnSet",
            "user",
            "kxUpnSet",
            "kxUpnSetX@pastukhov.lab",
            "KX UPN Set",
            "{dddddddd-0000-0000-0000-000000000103}",
            "1161",
        ),
        kx_object(
            "kxOwner",
            "user",
            "kxOwner",
            None,
            "KX Owner",
            "{dddddddd-0000-0000-0000-000000000104}",
            "1162",
        ),
        kx_object(
            "kxConflict",
            "user",
            "kxConflict",
            "kxOwner@pastukhov.lab",
            "KX Conflict",
            "{dddddddd-0000-0000-0000-000000000105}",
            "1163",
        ),
        kx_object(
            "kxAlias",
            "user",
            "kxAlias",
            "kxShort@pastukhov.lab",
            "KX Alias",
            "{dddddddd-0000-0000-0000-000000000106}",
            "1164",
        ),
        kx_object(
            "kxTrust",
            "user",
            "kxTrust",
            "kxTrust@pastukhov.lab",
            "KX Trust",
            "{dddddddd-0000-0000-0000-000000000107}",
            "1165",
        ),
        kx_object(
            "kxNoSpn",
            "user",
            "kxNoSpn",
            "kxNoSpn@pastukhov.lab",
            "KX No SPN",
            "{dddddddd-0000-0000-0000-000000000108}",
            "1166",
        ),
    ]
    added = []
    for obj in additions:
        if obj["id"] not in existing:
            snapshot["objects"].append(obj)
            added.append(obj["id"])
    return added


def components_from_row(row):
    return json.loads(row["name_components"])


def name_type_label(row):
    return row["name_type"].replace("_", "-")


def input_for(row):
    name_type = int(row["name_type_value"])
    principal = {"name_type": name_type, "name_string": components_from_row(row)}
    if row["scenario"] == "as_req_cname":
        return {"protocol": "Kerberos", "message_type": "AS-REQ", "cname": principal, "realm": row["realm"]}
    if row["scenario"] == "as_req_sname":
        return {
            "protocol": "Kerberos",
            "message_type": "AS-REQ",
            "principal_field": "sname",
            "sname": principal,
            "realm": row["realm"],
        }
    if row["scenario"] == "tgs_req_sname":
        return {"protocol": "Kerberos", "message_type": "TGS-REQ", "sname": principal, "realm": row["realm"]}
    raise ValueError(row["scenario"])


def local_object_id(selected):
    if selected == "10-23-RP-DC-01$":
        return "dc01"
    if selected in {"server_principal_found", "unknown_password_mismatch"}:
        return "dc01"
    return selected


def matched_field_for(case_id):
    if "DN" in case_id:
        return "distinguishedName"
    if "DOWNLEVEL" in case_id:
        return "domainNetBIOS+sAMAccountName"
    if "DNS-BACKSLASH" in case_id:
        return "domainFQDN+sAMAccountName"
    if "UPN" in case_id or "TRUST" in case_id:
        return "userPrincipalName"
    if "SPN" in case_id or "HTTP" in case_id or "HOST" in case_id or "CIFS" in case_id:
        return "servicePrincipalName"
    return "sAMAccountName"


def format_suffix(row, selected):
    case_id = row["case_id"]
    scenario = row["scenario"]
    components = components_from_row(row)
    if scenario == "as_req_cname":
        if "DNS-BACKSLASH" in case_id:
            return "dnsDownLevelLogonName"
        if "DN" in case_id:
            return "distinguishedName"
        if "CANONICAL" in case_id:
            return "canonicalName"
        if "DISPLAY" in case_id:
            return "displayName"
        if "OBJECTGUID" in case_id:
            return "objectGUID"
        if "OBJECTSID" in case_id:
            return "objectSid"
        if "SPN-CLIENT" in case_id:
            return "servicePrincipalName"
        if "DOWNLEVEL" in case_id:
            return "downLevelLogonName"
        if "MACHINE-NO-DOLLAR" in case_id:
            return "sAMAccountName+$"
        if "SHORT-UPN" in case_id:
            return "userPrincipalName"
        if "UPN-CONFLICT" in case_id and selected == "kxOwner":
            return "generatedUPN"
        if "IMPLICIT-UPN" in case_id or "UPNSET-GENERATED" in case_id:
            return "generatedUPN"
        if "UPN" in case_id or "TRUST" in case_id:
            return "userPrincipalName"
        return "sAMAccountName"
    if scenario in {"as_req_sname", "tgs_req_sname"}:
        if len(components) > 1 and components[0].casefold() == "krbtgt":
            return "krbtgt/sAMAccountName"
        if "UPN" in case_id:
            return "userPrincipalName"
        if "DOWNLEVEL" in case_id:
            return "downLevelLogonName"
        if "HTTP" in case_id or "HOST" in case_id or "CIFS" in case_id:
            return "servicePrincipalName"
        if "MACHINE" in case_id:
            return "sAMAccountName+$"
        return "sAMAccountName"
    return "principal"


def matched_format(row, selected=None):
    return f"{name_type_label(row)}/{format_suffix(row, selected)}"


def input_field(row):
    return "cname" if row["scenario"] == "as_req_cname" else "sname"


def branch(row):
    return CLIENT_BRANCH if row["scenario"] == "as_req_cname" else SERVER_BRANCH


def category(row):
    return "kerberos_client_lookup" if row["scenario"] == "as_req_cname" else "kerberos_server_lookup"


def title_for(row, semantic, selected):
    base = row["case_name"]
    nt = row["name_type"]
    if semantic == "true":
        obj = local_object_id(selected)
        return f"KDC: {base}, {nt} -> {obj}"
    if semantic == "unknown":
        return f"KDC: {base}, {nt} -> результат не определен"
    return f"KDC: {base}, {nt} -> объект не найден"


def description_for(row, semantic, selected):
    field = "cname" if row["scenario"] == "as_req_cname" else "sname"
    message = "AS-REQ" if row["scenario"].startswith("as_req") else "TGS-REQ"
    nt = row["name_type"]
    name_string = row["name_string"]
    if semantic == "true":
        obj = local_object_id(selected)
        result = f"найден объект {obj} через {matched_format(row, selected)}"
    elif semantic == "unknown":
        result = "формат не подтвержден: прогон не дал однозначного principal-lookup результата"
    else:
        result = f"объект не найден для {matched_format(row)}"
    return (
        f"Kerberos {message}: {field} name-type={row['name_type_value']} ({nt}), "
        f"name-string=[{name_string}], realm={row['realm']} -> {branch(row)}; "
        f"ожидаемый результат: {result}"
    )


def expected_for(row, semantic, selected):
    expected = {
        "resolved": semantic == "true",
        "protocol": "Kerberos",
        "algorithm_branch": branch(row),
    }
    if semantic == "true":
        expected.update(
            {
                "matched_object_id": local_object_id(selected),
            }
        )
    elif semantic == "unknown":
        expected.update(
            {
                "reason": "kdc_result_unknown",
            }
        )
    else:
        pass
    return expected


def semantic_for_group(group):
    true_rows = [row for row in group if row["resolved"] == "true"]
    if true_rows:
        selected = sorted({row["selected_object"] for row in true_rows if row["selected_object"]})
        if len(selected) != 1:
            raise ValueError(f"ambiguous selected object: {selected}")
        return "true", selected[0], true_rows[0]
    unknown_rows = [row for row in group if row["resolved"] == "unknown"]
    if unknown_rows:
        return "unknown", "", unknown_rows[0]
    return "false", "", group[0]


def compact_group_key(row, selected, semantic):
    return (
        row["scenario"],
        row["case_id"],
        tuple(components_from_row(row)),
        semantic,
        local_object_id(selected) if selected else "",
        format_suffix(row, selected),
    )


def compact_test_id_for(row, semantic, selected):
    cid = row["case_id"].lower().replace("-", "_")
    suffix = "found" if semantic == "true" else semantic
    if semantic == "true":
        suffix = local_object_id(selected).lower().replace("-", "_").replace("$", "machine")
    return f"kdc_{row['scenario']}_{cid}_{suffix}"


def name_type_summary(rows):
    ordered = sorted(rows, key=lambda row: int(row["name_type_value"]))
    return ", ".join(dict.fromkeys(row["name_type"] for row in ordered))


def representative_row(rows):
    preferred = [
        "NT_ENTERPRISE",
        "NT_PRINCIPAL",
        "NT_SRV_INST",
        "NT_MS_PRINCIPAL",
        "NT_UNKNOWN",
    ]
    by_type = {row["name_type"]: row for row in rows}
    for name_type in preferred:
        if name_type in by_type:
            return by_type[name_type]
    return sorted(rows, key=lambda row: int(row["name_type_value"]))[0]


def build_kdc_tests(rows):
    grouped = defaultdict(list)
    for row in rows:
        if row["domain_fqdn"] != DOMAIN:
            continue
        semantic = row["resolved"]
        selected = row["selected_object"] if semantic == "true" else ""
        grouped[compact_group_key(row, selected, semantic)].append(row)
    tests = []
    for key in sorted(grouped):
        group = grouped[key]
        semantic, selected, _ = semantic_for_group(group)
        row = representative_row(group)
        confirmed_types = name_type_summary(group)
        fmt = f"{matched_format(row, selected)}; confirmed NameType: {confirmed_types}"
        description = description_for(row, semantic, selected)
        description = f"{description}; confirmed NameType: {confirmed_types}"
        test_id = compact_test_id_for(row, semantic, selected)
        if test_id not in COMPACT_KDC_TEST_IDS:
            continue
        tests.append(
            {
                "id": test_id,
                "title": title_for(row, semantic, selected),
                "category": category(row),
                "format": fmt,
                "description": description,
                "input": input_for(row),
                "expected": expected_for(row, semantic, selected),
            }
        )
    return tests


def merge_tests(tests_data, kdc_tests):
    tests = tests_data["tests"]
    before = len(tests)
    existing_ids = {test["id"] for test in tests}
    tests = [test for test in tests if not test["id"].startswith("kdc_")]
    removed_old_kdc = before - len(tests)
    existing_ids = {test["id"] for test in tests}
    added = []
    for test in kdc_tests:
        if test["id"] not in existing_ids:
            tests.append(test)
            added.append(test["id"])
    tests_data["tests"] = tests
    return removed_old_kdc, added


def object_fields_for_readme(obj):
    spns = obj.get("servicePrincipalName") or []
    sid_history = obj.get("sIDHistory") or []
    values = [
        ("object_type", obj["object_type"]),
        ("sAMAccountName", obj["sAMAccountName"]),
        ("userPrincipalName", obj.get("userPrincipalName")),
        ("distinguishedName", obj["distinguishedName"]),
        ("canonicalName", obj["canonicalName"]),
        ("displayName", obj["displayName"]),
        ("objectGUID", obj["objectGUID"]),
        ("objectSid", obj["objectSid"]),
        ("servicePrincipalName", ", ".join(spns) if spns else "[]"),
        ("sIDHistory", ", ".join(sid_history) if sid_history else "[]"),
        ("domainFQDN", obj["domainFQDN"]),
        ("domainNetBIOS", obj["domainNetBIOS"]),
    ]
    return "<br>".join(f"- {key}: {md_cell(value)}" for key, value in values)


def md_cell(value):
    text = "" if value is None else str(value)
    return text.replace("\\", "\\\\").replace("\r\n", "\\n").replace("\n", "\\n").replace("|", "\\|")


def compact_object_fields(obj):
    keys = [
        "sAMAccountName",
        "userPrincipalName",
        "displayName",
        "domainFQDN",
        "domainNetBIOS",
        "distinguishedName",
        "canonicalName",
        "servicePrincipalName",
        "objectGUID",
        "objectSid",
        "sIDHistory",
    ]
    parts = []
    for key in keys:
        value = obj.get(key)
        if value in (None, "", []):
            continue
        if isinstance(value, list):
            value = ", ".join(value)
        parts.append(f"{key}={md_cell(value)}")
    return ", ".join(parts)


def object_reason(obj):
    reasons = {
        "kxBase": "Базовый пользователь из KDC-прогона для ordinary SAM, UPN, DN и negative cname cases.",
        "kxSvc": "Сервисная учетная запись из KDC-прогона с HTTP/HOST SPN.",
        "kxImplicit": "Пользователь из KDC-прогона без явного userPrincipalName для generated UPN.",
        "kxUpnSet": "Пользователь из KDC-прогона, у которого explicit UPN отличается от generated UPN.",
        "kxOwner": "Объект из KDC-прогона для explicit UPN vs generated UPN conflict: generated UPN.",
        "kxConflict": "Объект из KDC-прогона для explicit UPN vs generated UPN conflict: explicit UPN.",
        "kxAlias": "Объект из KDC-прогона для короткого имени, найденного через UPN prefix.",
        "kxTrust": "Объект из KDC-прогона для UPN-like значения с suffix pastukhov.lab.",
        "kxNoSpn": "Объект из KDC-прогона без SPN для negative server principal cases.",
    }
    return reasons.get(obj["id"], "Объект локального AD snapshot для тестов прототипа.")


def rebuild_object_table(readme, snapshot):
    start = readme.index("## Объекты в базе")
    try:
        end = readme.index("## Тестовые кейсы")
    except ValueError:
        end = readme.index("## Разделы тестов")
    lines = [
        "## Объекты в базе",
        "",
        "Все тесты используют одну базу `ad_snapshot.json`. Для Kerberos KDC-матрицы добавлены объекты `kx*`, которые соответствуют сущностям из `kerberos-corner-results-v2.zip/full_results.csv`.",
        "",
        "В таблице ниже колонка `id` соответствует полю `id` объекта, а в колонке \"Поля объекта\" перечислены все остальные поля из реального `ad_snapshot.json`.",
        "",
        "| id | Поля объекта | Зачем нужен |",
        "|---|---|---|",
    ]
    for obj in snapshot["objects"]:
        lines.append(f"| {obj['id']} | {object_fields_for_readme(obj)} | {object_reason(obj)} |")
    lines.append("")
    return readme[:start] + "\n".join(lines) + "\n" + readme[end:]


def readme_description(test, objects_by_id):
    inp = test["input"]
    expected = test["expected"]
    if inp.get("protocol") == "LDAP":
        name = ldap_request_value_for_readme(test)
        setup = ldap_setup_step(test, objects_by_id)
        result = expected_result_for_readme(test)
        return (
            f"1. {setup}<br>"
            f"2. Выполнить LDAP BindRequest.name={md_cell(name)}.<br>"
            f"3. Ожидаемый результат: {result}."
        )
    principal_field = (inp.get("principal_field") or "").casefold()
    if principal_field not in {"cname", "sname"}:
        principal_field = "cname" if inp.get("message_type") == "AS-REQ" else "sname"
    principal = inp.get(principal_field) or {}
    name_type = principal.get("name_type")
    name_string = principal.get("name_string") or []
    setup = kerberos_setup_step(test, objects_by_id)
    result = expected_result_for_readme(test)
    return (
        f"1. {setup}<br>"
        f"2. Выполнить {inp.get('message_type')} {principal_field} с name_string={kerberos_name_string_for_readme(test, name_string)}, realm={inp.get('realm')}, NameType={name_type}.<br>"
        f"3. Ожидаемый результат: {result}."
    )


def expected_result_for_readme(test):
    expected = test["expected"]
    documented_format = (test.get("format") or "").split(";")[0]
    if expected.get("resolved"):
        return f"найден объект {expected.get('matched_object_id')} через {expected.get('matched_format') or documented_format}"
    if expected.get("reason") == "kdc_result_unknown":
        return "результат principal lookup не определен."
    return "объект не найден"


def object_id_from_test(test, objects_by_id=None):
    expected = test["expected"]
    if expected.get("matched_object_id"):
        return expected["matched_object_id"]
    test_id = test["id"]
    input_text = json.dumps(test.get("input", {}), ensure_ascii=False)
    object_ids = list((objects_by_id or {}).keys()) or [
        "userA",
        "userB",
        "userImplicit",
        "userUpnSet",
        "userUpnAlias",
        "userImplicitOwner",
        "userConflict",
        "kxBase",
        "kxSvc",
        "kxImplicit",
        "kxUpnSet",
        "kxOwner",
        "kxConflict",
        "kxAlias",
        "kxNoSpn",
        "dc01",
        "krbtgt",
    ]
    for object_id in object_ids:
        if object_id.lower() in test_id.lower() or object_id.lower() in input_text.lower():
            return object_id
    aliases = {
        "user3": "userUpnAlias",
        "userupnsetx": "userUpnSet",
        "10-23-rp-dc-01": "dc01",
    }
    lowered = f"{test_id} {input_text}".lower()
    for needle, object_id in aliases.items():
        if needle in lowered:
            return object_id
    if test_id == "ldap_sam_userA_not_accepted":
        return "userA"
    return None


def ldap_setup_step(test, objects_by_id):
    object_id = object_id_from_test(test, objects_by_id)
    obj = objects_by_id.get(object_id or "")
    if obj:
        object_type = "компьютер" if obj.get("object_type") == "computer" else "пользователя"
        if test["id"].startswith("ldap_guid_"):
            return f"Создать {object_type} {object_id} с полями: sAMAccountName={md_cell(obj.get('sAMAccountName'))}, userPrincipalName={md_cell(obj.get('userPrincipalName'))}, domainFQDN={md_cell(obj.get('domainFQDN'))}; скопировать его objectGUID."
        if "object_sid" in test["id"]:
            return f"Создать {object_type} {object_id} с полями: sAMAccountName={md_cell(obj.get('sAMAccountName'))}, userPrincipalName={md_cell(obj.get('userPrincipalName'))}, domainFQDN={md_cell(obj.get('domainFQDN'))}; скопировать его objectSid."
        return f"Создать {object_type} {object_id} с полями: {compact_object_fields(obj)}."
    return "Создать объект с полями, указанными во входном LDAP principal."


def ldap_request_value_for_readme(test):
    name = test["input"].get("request", {}).get("name", "")
    if test["id"].startswith("ldap_guid_"):
        object_id = test["expected"].get("matched_object_id") or object_id_from_test(test) or "пользователя"
        return f"<objectGUID {object_id}>"
    if "object_sid" in test["id"]:
        object_id = test["expected"].get("matched_object_id") or object_id_from_test(test) or "пользователя"
        return f"<objectSid {object_id}>"
    return name


def kerberos_name_string_for_readme(test, name_string):
    test_id = test["id"]
    if "objectguid" in test_id:
        return '["<objectGUID пользователя kxBase>"]'
    if "objectsid" in test_id:
        return '["<objectSid пользователя kxBase>"]'
    return md_cell(json.dumps(name_string, ensure_ascii=False))


def kerberos_setup_step(test, objects_by_id):
    test_id = test["id"]
    expected = test["expected"]
    matched = expected.get("matched_object_id")
    fmt = expected.get("matched_format") or test.get("format") or ""
    if "objectguid" in test_id:
        return "Создать пользователя kxBase с sAMAccountName=kxBase и userPrincipalName=kxBase@pastukhov.lab; скопировать его objectGUID."
    if "objectsid" in test_id:
        return "Создать пользователя kxBase с sAMAccountName=kxBase и userPrincipalName=kxBase@pastukhov.lab; скопировать его objectSid."
    if "canonical" in test_id:
        return "Создать пользователя kxBase с canonicalName=pastukhov.lab/Users/kxBase."
    if "display" in test_id:
        return "Создать пользователя kxBase с displayName=KX Base."
    if "spn_client" in test_id or "http" in test_id or "host" in test_id:
        return "Создать сервисную учетную запись kxSvc с SPN HTTP/kxspn22.pastukhov.lab, HTTP/kxspn22, HOST/kxspn22.pastukhov.lab и HOST/kxspn22."
    if "nospn" in test_id:
        return "Создать учетную запись kxNoSpn с sAMAccountName=kxNoSpn и userPrincipalName=kxNoSpn@pastukhov.lab; servicePrincipalName оставить пустым."
    if "implicit_upn" in test_id:
        return "Создать пользователя kxImplicit с sAMAccountName=kxImplicit, domainFQDN=pastukhov.lab и пустым userPrincipalName."
    if "upn_conflict" in test_id:
        return "Создать kxOwner без userPrincipalName и kxConflict с userPrincipalName=kxOwner@pastukhov.lab."
    if "upnset" in test_id:
        return "Создать пользователя kxUpnSet с sAMAccountName=kxUpnSet и userPrincipalName=kxUpnSetX@pastukhov.lab."
    if "short_upn" in test_id:
        return "Создать пользователя kxAlias с sAMAccountName=kxAlias и userPrincipalName=kxShort@pastukhov.lab."
    if "krbtgt" in test_id:
        return "Создать или использовать встроенную учетную запись krbtgt в домене pastukhov.lab с sAMAccountName=krbtgt и domainFQDN=pastukhov.lab."
    if "machine" in test_id or "cifs_dc" in test_id or matched == "dc01":
        return "Создать объект контроллера домена dc01 с sAMAccountName=10-23-RP-DC-01$ и SPN для HOST/CIFS имени контроллера."
    if "downlevel" in test_id:
        return "Создать пользователя kxBase с sAMAccountName=kxBase, domainNetBIOS=PASTUKHOV и domainFQDN=pastukhov.lab."
    if "dns_backslash" in test_id:
        return "Создать пользователя kxBase с sAMAccountName=kxBase и domainFQDN=pastukhov.lab."
    if matched == "kxSvc" or "svc" in test_id:
        return "Создать сервисную учетную запись kxSvc с sAMAccountName=kxSvc, userPrincipalName=kxSvc@pastukhov.lab и назначенными SPN."
    if matched == "kxBase" or "sam_base" in test_id or "upn_base" in test_id or "dn" in test_id:
        return "Создать пользователя kxBase с sAMAccountName=kxBase, userPrincipalName=kxBase@pastukhov.lab и distinguishedName=CN=kxBase,CN=Users,DC=pastukhov,DC=lab."
    object_id = object_id_from_test(test, objects_by_id)
    obj = objects_by_id.get(object_id or "")
    if obj:
        object_type = "компьютер" if obj.get("object_type") == "computer" else "учетную запись"
        return f"Создать {object_type} {object_id} с полями: {compact_object_fields(obj)}."
    return f"Создать тестовую учетную запись с полями: sAMAccountName=<account>, userPrincipalName=<account>@pastukhov.lab, domainFQDN=pastukhov.lab; использовать ее для проверки {fmt}."


def readme_result(test):
    return expected_result_for_readme(test)


def test_source(test):
    if test["id"].startswith("kdc_"):
        return "kerberos-corner-results-v2.zip/full_results.csv"
    if test["category"].startswith("kerberos"):
        return "kerberos-corner-results-v2.zip/full_results.csv + статья: Kerberos Principal Lookup"
    if test["category"].startswith("ldap"):
        return "Статья и проверка WinServer: порядок LDAP-форматов"
    return "tests.json"


def rebuild_test_sections(readme, tests):
    counts = Counter(test["category"] for test in tests)
    snapshot = load_json(SNAPSHOT_PATH)
    objects_by_id = {obj["id"]: obj for obj in snapshot["objects"]}
    try:
        start = readme.index("## Тестовые кейсы")
    except ValueError:
        start = readme.index("## Разделы тестов")
    end = readme.index("## Как запускать")
    lines = [
        "## Разделы тестов",
        "",
        "| id раздела | Название | Кол-во тестов |",
        "|---|---|---|",
    ]
    seen = []
    for test in tests:
        if test["category"] not in seen:
            seen.append(test["category"])
    for category in seen:
        lines.append(f"| `{category}` | {CATEGORY_LABELS.get(category, category)} | {counts[category]} |")
    lines.extend(
        [
            "",
            "## Таблица тестов и corner cases",
            "",
            "| № | Название | Описание | Формат / ветка | Ожидаемый результат | Откуда взяли | Раздел | id |",
            "|---|---|---|---|---|---|---|---|",
        ]
    )
    for index, test in enumerate(tests, 1):
        section = CATEGORY_LABELS.get(test["category"], test["category"])
        lines.append(
            f"| {index} | {md_cell(test['title'])} | {readme_description(test, objects_by_id)} | {md_cell(test.get('format') or '-')} | {md_cell(readme_result(test))} | {md_cell(test_source(test))} | {md_cell(section)} | `{md_cell(test['id'])}` |"
        )
    lines.append("")
    return readme[:start] + "\n".join(lines) + "\n" + readme[end:]


def validate(tests_data, snapshot):
    object_ids = {obj["id"] for obj in snapshot["objects"]}
    missing = sorted(
        {
            test["expected"].get("matched_object_id")
            for test in tests_data["tests"]
            if test["expected"].get("matched_object_id") and test["expected"].get("matched_object_id") not in object_ids
        }
    )
    if missing:
        raise ValueError(f"missing matched_object_id in snapshot: {missing}")


def main():
    tests_data = load_json(TESTS_PATH)
    snapshot = load_json(SNAPSHOT_PATH)
    rows = load_kdc_rows()
    initial_tests = len(tests_data["tests"])
    initial_objects = len(snapshot["objects"])
    added_objects = ensure_snapshot_objects(snapshot)
    kdc_tests = build_kdc_tests(rows)
    removed_old_kdc, added_tests = merge_tests(tests_data, kdc_tests)
    validate(tests_data, snapshot)
    readme = README_PATH.read_text(encoding="utf-8")
    readme = rebuild_object_table(readme, snapshot)
    readme = rebuild_test_sections(readme, tests_data["tests"])
    dump_json(SNAPSHOT_PATH, snapshot)
    dump_json(TESTS_PATH, tests_data)
    README_PATH.write_text(readme, encoding="utf-8")
    print(json.dumps({
        "initial_tests": initial_tests,
        "final_tests": len(tests_data["tests"]),
        "initial_objects": initial_objects,
        "final_objects": len(snapshot["objects"]),
        "added_objects": added_objects,
        "kdc_tests_generated": len(kdc_tests),
        "removed_old_kdc": removed_old_kdc,
        "added_tests": len(added_tests),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
