"""CLI для ручных проверок и тестов, описанных в JSON."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .repository import ADSnapshotRepository
from .resolver import resolve_event
from .test_runner import (
    list_tests,
    load_tests,
    print_summary,
    print_test_result,
    run_all_tests,
    run_test,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = PROJECT_ROOT / "ad_snapshot.json"
DEFAULT_TESTS = PROJECT_ROOT / "tests.json"
AS_REQ_NAME_TYPES = {
    1: "KRB5-NT-PRINCIPAL",
    10: "KRB5-NT-ENTERPRISE-PRINCIPAL",
}
TGS_REQ_NAME_TYPES = {
    1: "KRB5-NT-PRINCIPAL",
    2: "KRB5-NT-SRV-INST",
    3: "KRB5-NT-SRV-HST",
    10: "KRB5-NT-ENTERPRISE-PRINCIPAL",
}


def load_config(path: Path = DEFAULT_DB) -> tuple[ADSnapshotRepository, dict[str, list[str]]]:
    # Загружаем одну JSON-базу: из нее строится repository для поиска объектов,
    # а spn_mappings отдельно передаются в LDAP MapSPN step.
    with path.open("r", encoding="utf-8") as file:
        raw = json.load(file)
    repository = ADSnapshotRepository.load(path)
    spn_mappings = raw.get("spn_mappings") or {}
    return repository, spn_mappings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Прототип AD-like name resolution")
    parser.add_argument("--db", default=str(DEFAULT_DB), help="Путь к JSON-базе AD snapshot")
    parser.add_argument("--tests", default=str(DEFAULT_TESTS), help="Путь к JSON-файлу тестов")
    parser.add_argument("--manual", action="store_true", help="Запустить ручной интерактивный режим")
    parser.add_argument("--list-tests", action="store_true", help="Показать список тестов из tests.json")
    parser.add_argument("--run-all", action="store_true", help="Запустить все тесты")
    parser.add_argument("--run-category", help="Запустить тесты из одного раздела")
    args = parser.parse_args(argv)

    repository, spn_mappings = load_config(Path(args.db))
    tests = load_tests(args.tests)

    # CLI поддерживает два способа проверки:
    # 1. автоматические тесты из tests.json;
    # 2. ручной ввод события, похожего на уже разобранный трафик.
    if args.list_tests:
        list_tests(tests)
        return 0
    if args.run_category:
        # Пустая категория почти всегда означает опечатку, поэтому возвращаем
        # ошибку вместо "0 passed, 0 failed".
        if not any(test.category == args.run_category for test in tests):
            print(f"Тесты для категории не найдены: {args.run_category}")
            return 2
        results = run_all_tests(tests, repository, spn_mappings, args.run_category)
        for result in results:
            print_test_result(result, verbose=False)
        print_summary(results)
        return 0 if all(result["passed"] for result in results) else 1
    if args.run_all:
        results = run_all_tests(tests, repository, spn_mappings)
        for result in results:
            print_test_result(result, verbose=False)
        print_summary(results)
        return 0 if all(result["passed"] for result in results) else 1
    if args.manual:
        run_manual_mode(repository, spn_mappings)
        return 0

    run_interactive_menu(repository, spn_mappings, tests)
    return 0


def run_interactive_menu(repository, spn_mappings, tests) -> None:
    while True:
        print("\nВыберите режим:")
        print("1. Ручной ввод события")
        print("2. Автоматические тесты")
        print("3. Выход")
        choice = input("> ").strip()
        if choice == "1":
            run_manual_mode(repository, spn_mappings)
        elif choice == "2":
            run_tests_menu(repository, spn_mappings, tests)
        elif choice == "3":
            return
        else:
            print("Неизвестный пункт меню.")


def run_tests_menu(repository, spn_mappings, tests) -> None:
    while True:
        print("\nТестовый режим:")
        print("1. Показать список тестов")
        print("2. Выбрать тест из списка")
        print("3. Запустить все тесты")
        print("4. Запустить раздел тестов")
        print("5. Назад")
        choice = input("> ").strip()
        if choice == "1":
            list_tests(tests)
        elif choice == "2":
            list_tests(tests)
            index_raw = input("Введите номер теста: ").strip()
            if not index_raw.isdigit() or not (1 <= int(index_raw) <= len(tests)):
                print("Некорректный номер.")
                continue
            print_test_result(run_test(tests[int(index_raw) - 1], repository, spn_mappings), verbose=True)
        elif choice == "3":
            results = run_all_tests(tests, repository, spn_mappings)
            for result in results:
                print_test_result(result, verbose=False)
            print_summary(results)
        elif choice == "4":
            categories = sorted({test.category for test in tests})
            print("Доступные разделы:", ", ".join(categories))
            category = input("Введите раздел: ").strip()
            if not any(test.category == category for test in tests):
                print(f"Тесты для категории не найдены: {category}")
                continue
            results = run_all_tests(tests, repository, spn_mappings, category)
            for result in results:
                print_test_result(result, verbose=False)
            print_summary(results)
        elif choice == "5":
            return
        else:
            print("Неизвестный пункт меню.")


def run_manual_mode(repository, spn_mappings) -> None:
    # Ручной режим не имитирует старый "login string -> traffic" слой.
    # Пользователь вводит то, что parser трафика уже должен был бы достать:
    # LDAP BindRequest.name или Kerberos principal fields.
    print("\nВыберите протокол:")
    print("1. LDAP")
    print("2. Kerberos")
    protocol_choice = input("> ").strip()
    if protocol_choice == "1":
        event = prompt_ldap_event()
    elif protocol_choice == "2":
        event = prompt_kerberos_event()
    else:
        print("Неизвестный протокол.")
        return

    result = resolve_event(event, repository, spn_mappings)
    print("\nКраткий итог:")
    print_human_summary(result.to_dict(include_object=False))
    print_cross_domain_note(event, result)
    print("\nJSON-результат:")
    print(json.dumps(result.to_dict(include_object=False), ensure_ascii=False, indent=2))
    if not result.resolved and result.trace:
        print_failure_explanation(result.to_dict(include_object=False), result.trace)
        print_trace(result.trace)


def prompt_ldap_event() -> dict[str, Any]:
    print("\nLDAP Simple Bind: используется поле BindRequest.name.")
    print("Можно вводить варианты из таблицы статьи:")
    print("  1. distinguishedName: CN=userA,CN=Users,DC=pastukhov,DC=lab")
    print("  2. userPrincipalName: userA@pastukhov.lab")
    print("  3. generated UPN: userImplicit@pastukhov.lab")
    print("  4. Down-Level Logon Name: PASTUKHOV\\userA")
    print("  5. canonicalName: pastukhov.lab/Users/userA")
    print("  6. objectGUID: {5c69b042-e0e9-475a-ae37-1751ef9e05e7}")
    print("  7. displayName: User A")
    print("  8. servicePrincipalName: HTTP/userA")
    print("  9. MapSPN: HOST/userA")
    print(" 10. objectSid: S-1-5-21-2845156888-2425353457-3474467337-1114")
    print(" 11. sIDHistory: S-1-5-21-2845156888-2425353457-3474467337-5114")
    print(" 12. canonicalName с LF: pastukhov.lab/Users\\nuserA")
    name = input("Введите BindRequest.name: ").strip()
    domain_context = input("Доменный контекст (пусто = без контекста; пример pastukhov.lab): ").strip()
    event: dict[str, Any] = {
        "protocol": "LDAP",
        "bind_kind": "simple",
        "request": {"operation": "bindRequest", "name": name},
    }
    # Пустой domain_context сохраняем именно пустым: ручной ввод должен
    # передавать resolver только то, что пользователь явно указал.
    if domain_context:
        event["domain_context"] = domain_context
    return event


def prompt_kerberos_event() -> dict[str, Any]:
    print("\nKerberos: вводятся поля уже разобранного principal из трафика.")
    print("AS-REQ использует cname / Client Principal Lookup.")
    print("TGS-REQ использует sname / Server Principal Lookup.")
    while True:
        # message_type определяет, какое поле principal будет использовано:
        # cname для AS-REQ или sname для TGS-REQ.
        print("\nТип сообщения:")
        print("1. AS-REQ")
        print("2. TGS-REQ")
        message_choice = input("> ").strip()
        if message_choice == "1":
            message_type = "AS-REQ"
            principal_key = "cname"
            allowed_name_types = AS_REQ_NAME_TYPES
            break
        if message_choice == "2":
            message_type = "TGS-REQ"
            principal_key = "sname"
            allowed_name_types = TGS_REQ_NAME_TYPES
            break
        print("Некорректный тип сообщения. Введите 1 или 2.")

    print_kerberos_name_type_hints(message_type, allowed_name_types)
    while True:
        # name_type оставляем числом, как в реальном Kerberos principal.
        raw_name_type = input("Введите name_type: ").strip()
        try:
            name_type = int(raw_name_type)
        except ValueError:
            print("name_type должен быть числом.")
            continue
        if name_type in allowed_name_types:
            break
        supported = ", ".join(str(value) for value in allowed_name_types)
        print(f"Для выбранной ветки поддерживаются name_type: {supported}.")

    print_kerberos_name_string_hints(message_type, name_type)
    while True:
        # name_string[] в Kerberos является массивом компонентов, поэтому в CLI
        # вводим компоненты через запятую: service,host.
        components = [part.strip() for part in input("name_string[]: ").split(",") if part.strip()]
        if components:
            break
        print("name_string[] не должен быть пустым.")

    default_realm = infer_realm_default(message_type, name_type, components)
    if default_realm:
        realm_prompt = f"realm [{default_realm}]: "
    else:
        realm_prompt = "realm (например PASTUKHOV.LAB; можно оставить пустым): "
    realm = input(realm_prompt).strip() or default_realm
    return {
        "protocol": "Kerberos",
        "message_type": message_type,
        principal_key: {"name_type": name_type, "name_string": components},
        "realm": realm,
    }


def print_kerberos_name_type_hints(message_type: str, allowed_name_types: dict[int, str]) -> None:
    print("\nДоступные name_type для выбранной ветки:")
    for number, name in allowed_name_types.items():
        print(f"{number:<2} = {name}")
    if message_type == "AS-REQ":
        print("AS-REQ / cname обычно проверяет пользователя: UPN-like строку или account name.")
    else:
        print("TGS-REQ / sname обычно проверяет сервисный principal: service,host или одноэлементное account name.")


def print_kerberos_name_string_hints(message_type: str, name_type: int) -> None:
    print("\nВведите name_string[] через запятую, как массив компонентов Kerberos principal.")
    if message_type == "AS-REQ" and name_type == 10:
        print("NT-ENTERPRISE / client: userA@pastukhov.lab")
    elif message_type == "AS-REQ" and name_type == 1:
        print("NT-PRINCIPAL / client: userA")
    elif message_type == "TGS-REQ" and name_type in {2, 3}:
        print("NT-SRV-INST/HST / server: cifs,10-23-RP-DC-01.pastukhov.lab")
        print("Одноэлементный fallback: 10-23-RP-DC-01")
    elif message_type == "TGS-REQ" and name_type == 1:
        print("NT-PRINCIPAL / server: cifs,10-23-RP-DC-01.pastukhov.lab")
        print("Одноэлементный fallback: 10-23-RP-DC-01")
    elif message_type == "TGS-REQ" and name_type == 10:
        print("NT-ENTERPRISE / server: HTTP/userA или cifs/10-23-RP-DC-01.pastukhov.lab")
    print("LDAP DN вида CN=...,DC=... сюда вводить не нужно: это формат для LDAP BindRequest.name.")


def infer_realm_default(message_type: str, name_type: int, components: list[str]) -> str:
    # realm остается отдельным полем события. Эта функция только предлагает удобный default
    # для ручного CLI; resolver получает realm как обычное входное поле.
    if not components:
        return ""
    first = components[0]
    if "@" in first and first.count("@") == 1:
        _, suffix = first.split("@", 1)
        if suffix:
            return suffix.upper()
    if message_type == "TGS-REQ" and len(components) >= 2:
        host = components[1]
        parts = host.split(".", 1)
        if len(parts) == 2 and parts[1]:
            return parts[1].upper()
    return ""


def print_human_summary(result: dict[str, Any]) -> None:
    if result.get("resolved"):
        print(
            "Найден объект "
            f"{result.get('matched_object_id')} через {result.get('matched_format')} "
            f"(поле {result.get('matched_field')})."
        )
        return
    reason = result.get("reason") or "unknown"
    detected_format = result.get("detected_format")
    if detected_format:
        print(f"Формат имени определен: {detected_format}.")
    print(f"Объект не разрешен: {reason}.")


def print_cross_domain_note(event: dict[str, Any], result: Any) -> None:
    if not result.resolved or result.matched_object is None:
        return
    context_name, context_value = input_domain_context(event)
    if not context_value:
        return
    obj = result.matched_object
    if domain_context_matches_object(obj, context_value):
        return
    print(
        "Заметка: "
        f"{context_name} = {context_value}, "
        f"а найденный объект находится в домене {obj.domainFQDN} ({obj.domainNetBIOS}). "
        "В PoC это допустимо: продукт сопоставляет полные идентификаторы по AD snapshot."
    )


def input_domain_context(event: dict[str, Any]) -> tuple[str, str | None]:
    protocol = (event.get("protocol") or "").casefold()
    if protocol == "kerberos":
        return "realm", event.get("realm")
    if protocol == "ldap":
        return "domain_context", event.get("domain_context")
    return "domain_context", None


def domain_context_matches_object(obj: Any, context: str | None) -> bool:
    if not context:
        return True
    context_norm = context.strip().casefold()
    return context_norm in {
        obj.domainFQDN.strip().casefold(),
        obj.domainNetBIOS.strip().casefold(),
    }


def print_failure_explanation(result: dict[str, Any], trace: list[dict[str, Any]]) -> None:
    # Это не часть алгоритма. Это UX-слой поверх trace, чтобы руками было проще
    # понять, почему строка не разрешилась.
    print("\nПояснение:")
    reason = result.get("reason")
    if reason == "object_not_found":
        print("- Объект не найден.")
    elif reason == "not_unique":
        print("- Найдено несколько совпадений; stable JSON не раскрывает candidate ids.")
    else:
        print(f"- Resolution завершился без найденного объекта: {reason or 'unknown'}.")

    detected_format = result.get("detected_format")
    if detected_format:
        print(f"- Определенный формат имени: {detected_format}.")

    upn_step = _trace_step(trace, "userPrincipalName")
    generated_upn_step = _trace_step(trace, "generatedUPN")
    if upn_step or generated_upn_step:
        print("- Строка похожа на UPN.")
    if upn_step and upn_step.get("matched_count") is not None:
        print(f"- Проверка userPrincipalName дала {upn_step['matched_count']} совпадений.")
    if generated_upn_step and generated_upn_step.get("matched_count") is not None:
        print(f"- Проверка generated UPN дала {generated_upn_step['matched_count']} совпадений.")
    other_zero_steps = [
        item
        for item in trace
        if item.get("matched_count") == 0
        and item.get("step") not in {"userPrincipalName", "generatedUPN"}
    ]
    if other_zero_steps:
        print("- Остальные применимые форматы также не нашли объект.")
    print("- Подробная техническая трасса ниже.")


def _trace_step(trace: list[dict[str, Any]], step_name: str) -> dict[str, Any] | None:
    return next((item for item in trace if item.get("step") == step_name), None)


def print_trace(trace: list[dict[str, Any]]) -> None:
    print("\nTrace проверки:")
    for index, item in enumerate(trace, 1):
        step = item.get("step") or item.get("branch") or "step"
        field = item.get("lookup_field", "-")
        value = item.get("lookup_value", "-")
        count = item.get("matched_count", "-")
        syntax = item.get("syntax_match")
        syntax_text = "" if syntax is None else f", syntax={syntax}"
        print(f"{index:02d}. {step}: field={field}, value={value}, matches={count}{syntax_text}")
