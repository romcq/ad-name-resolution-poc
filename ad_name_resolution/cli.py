"""Command line interface for manual checks and JSON-defined test cases."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .repository import ADSnapshotRepository
from .resolver import resolve_event
from .test_runner import (
    find_test_by_id,
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
SUPPORTED_KRB_NAME_TYPES = {1, 2, 3, 10}


def load_config(path: Path = DEFAULT_DB) -> tuple[ADSnapshotRepository, dict[str, list[str]]]:
    # Загружаем одну JSON-базу: из нее строится repository для поиска объектов,
    # а spn_mappings отдельно передаются в LDAP MapSPN step.
    with path.open("r", encoding="utf-8") as file:
        raw = json.load(file)
    repository = ADSnapshotRepository.load(path)
    spn_mappings = raw.get("spn_mappings") or {}
    return repository, spn_mappings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AD-like name resolution prototype")
    parser.add_argument("--db", default=str(DEFAULT_DB), help="Path to AD snapshot JSON")
    parser.add_argument("--tests", default=str(DEFAULT_TESTS), help="Path to tests JSON")
    parser.add_argument("--manual", action="store_true", help="Run manual interactive mode")
    parser.add_argument("--list-tests", action="store_true", help="List tests from tests.json")
    parser.add_argument("--run-all", action="store_true", help="Run all tests")
    parser.add_argument("--run-category", help="Run tests from one category")
    parser.add_argument("--run-test", help="Run one test by id")
    args = parser.parse_args(argv)

    repository, spn_mappings = load_config(Path(args.db))
    tests = load_tests(args.tests)

    # CLI поддерживает два способа проверки:
    # 1. автоматические тесты из tests.json;
    # 2. ручной ввод события, похожего на уже разобранный трафик.
    if args.list_tests:
        list_tests(tests)
        return 0
    if args.run_test:
        # Для CI/скриптов важно различать "тест упал" и "тест не найден".
        test = find_test_by_id(tests, args.run_test)
        if test is None:
            print(f"Тест не найден: {args.run_test}")
            return 2
        result = run_test(test, repository, spn_mappings)
        print_test_result(result, verbose=True)
        return 0 if result["passed"] else 1
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
        print("3. Запустить тест по id")
        print("4. Запустить все тесты")
        print("5. Запустить раздел тестов")
        print("6. Назад")
        choice = input("> ").strip()
        if choice == "1":
            list_tests(tests)
        elif choice == "2":
            list_tests(tests)
            index_raw = input("Введите номер теста: ").strip()
            if not index_raw.isdigit() or not (1 <= int(index_raw) <= len(tests)):
                print("Некорректный номер.")
                continue
            print_test_result(run_test(tests[int(index_raw) - 1], repository, spn_mappings))
        elif choice == "3":
            test_id = input("Введите id теста: ").strip()
            test = find_test_by_id(tests, test_id)
            if test is None:
                print("Тест не найден.")
                continue
            print_test_result(run_test(test, repository, spn_mappings))
        elif choice == "4":
            results = run_all_tests(tests, repository, spn_mappings)
            for result in results:
                print_test_result(result, verbose=False)
            print_summary(results)
        elif choice == "5":
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
        elif choice == "6":
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
    print("\nJSON-результат:")
    print(json.dumps(result.to_dict(include_object=False), ensure_ascii=False, indent=2))
    if not result.resolved and result.trace:
        print_failure_explanation(result.to_dict(include_object=False), result.trace)
        print_trace(result.trace)


def prompt_ldap_event() -> dict[str, Any]:
    print("\nLDAP Simple Bind: используется поле BindRequest.name.")
    print("Примеры:")
    print("  userA@pastukhov.lab")
    print("  PASTUKHOV\\userA")
    print("  CN=userA,CN=Users,DC=pastukhov,DC=lab")
    print("  pastukhov.lab/Users/userA")
    name = input("Введите BindRequest.name: ").strip()
    domain_context = input("Доменный контекст (пусто = без контекста; пример pastukhov.lab): ").strip()
    event: dict[str, Any] = {
        "protocol": "LDAP",
        "bind_kind": "simple",
        "request": {"operation": "bindRequest", "name": name},
    }
    # Пустой domain_context сохраняем именно пустым: это позволяет проверить
    # not_unique случаи между доменами, а не подставлять pastukhov.lab молча.
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
            break
        if message_choice == "2":
            message_type = "TGS-REQ"
            principal_key = "sname"
            break
        print("Некорректный тип сообщения. Введите 1 или 2.")

    print("\nname_type:")
    print("1  = KRB5-NT-PRINCIPAL")
    print("2  = KRB5-NT-SRV-INST")
    print("3  = KRB5-NT-SRV-HST")
    print("10 = KRB5-NT-ENTERPRISE-PRINCIPAL")
    while True:
        # name_type оставляем числом, как в реальном Kerberos principal.
        raw_name_type = input("Введите name_type: ").strip()
        try:
            name_type = int(raw_name_type)
        except ValueError:
            print("name_type должен быть числом.")
            continue
        if name_type in SUPPORTED_KRB_NAME_TYPES:
            break
        print("Для этого прототипа поддерживаются только name_type: 1, 2, 3, 10.")

    print("\nВведите name_string[] через запятую.")
    print("Пример AS-REQ UPN: userA@pastukhov.lab")
    print("Пример TGS-REQ service/host: cifs,10-23-RP-DC-01.pastukhov.lab")
    while True:
        # name_string[] в Kerberos является массивом компонентов, поэтому в CLI
        # вводим компоненты через запятую: service,host.
        components = [part.strip() for part in input("name_string[]: ").split(",") if part.strip()]
        if components:
            break
        print("name_string[] не должен быть пустым.")

    realm = input("realm [PASTUKHOV.LAB]: ").strip() or "PASTUKHOV.LAB"
    return {
        "protocol": "Kerberos",
        "message_type": message_type,
        principal_key: {"name_type": name_type, "name_string": components},
        "realm": realm,
    }


def print_human_summary(result: dict[str, Any]) -> None:
    if result.get("resolved"):
        print(
            "Найден объект "
            f"{result.get('matched_object_id')} через {result.get('matched_format')} "
            f"(поле {result.get('matched_field')})."
        )
        return
    reason = result.get("reason") or "unknown"
    print(f"Объект не разрешен: {reason}.")


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
