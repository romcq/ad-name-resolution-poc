"""Загрузка, запуск и печать тестов резолвера из JSON."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .repository import ADSnapshotRepository
from .resolver import resolve_event


@dataclass(frozen=True)
class TestCase:
    id: str
    category: str
    title: str
    format: str
    description: str
    input: dict[str, Any]
    expected: dict[str, Any]


CATEGORY_LABELS = {
    "ldap_table": "LDAP: базовые форматы имени",
    "ldap_algorithm": "LDAP: дополнительные форматы",
    "ldap_dn_special": "LDAP: DN со спецсимволами",
    "ldap_corner": "LDAP: корнеры и приоритет форматов",
    "kerberos_client_lookup": "Kerberos: AS-REQ / Client Principal Lookup",
    "kerberos_server_lookup": "Kerberos: TGS-REQ / Server Principal Lookup",
}


def load_tests(path: str | Path) -> list[TestCase]:
    with Path(path).open("r", encoding="utf-8") as file:
        raw = json.load(file)
    return [
        TestCase(
            id=item["id"],
            category=item.get("category", "без_категории"),
            title=item.get("title") or item["description"],
            format=item.get("format") or "-",
            description=item["description"],
            input=item["input"],
            expected=item["expected"],
        )
        for item in raw["tests"]
    ]


def list_tests(tests: list[TestCase]) -> None:
    current_category = None
    for index, test in enumerate(tests, 1):
        if test.category != current_category:
            current_category = test.category
            category_label = CATEGORY_LABELS.get(test.category, test.category)
            print(f"\n== {category_label} ({test.category}) ==")
        print(f"{index:02d}. {test.title}")
        print(f"    формат: {test.format} | {expected_summary(test)}")
        print(f"    вход: {input_summary(test)}")
        print(f"    id: {test.id}")


def input_summary(test: TestCase) -> str:
    event = test.input
    if event.get("protocol") == "LDAP":
        request = event.get("request") or {}
        return f'BindRequest.name="{request.get("name", "")}"'
    if event.get("protocol") == "Kerberos":
        message_type = event.get("message_type")
        principal_key = "cname" if message_type == "AS-REQ" else "sname"
        principal = event.get(principal_key) or {}
        name_string = ",".join(principal.get("name_string") or [])
        return (
            f"{message_type} {principal_key}: "
            f"name_type={principal.get('name_type')}, "
            f"name_string=[{name_string}], "
            f"realm={event.get('realm') or '-'}"
        )
    return str(event)


def expected_summary(test: TestCase) -> str:
    expected = test.expected
    if expected.get("resolved") is True:
        return f"ожидается объект {expected.get('matched_object_id')} ({expected.get('matched_format')})"
    detected = expected.get("detected_format") or expected.get("matched_format") or "-"
    return f"ожидается {expected.get('reason')} (формат: {detected})"


def run_test(
    test: TestCase,
    repository: ADSnapshotRepository,
    spn_mappings: dict[str, list[str]],
) -> dict[str, Any]:
    # Тесты не содержат отдельной логики resolution. Они просто отправляют
    # input в тот же resolver, что и ручной режим, и сравнивают selected поля.
    actual_result = resolve_event(test.input, repository, spn_mappings)
    # В expected обычно проверяются только важные поля. Например, тест может
    # не проверять input_field, если кейс посвящен matched_format.
    actual = actual_result.to_dict(include_object=False, include_trace=False)
    mismatches = {}
    for key, expected_value in test.expected.items():
        actual_value = actual.get(key)
        if actual_value != expected_value:
            mismatches[key] = {"expected": expected_value, "actual": actual_value}
    return {
        "id": test.id,
        "category": test.category,
        "title": test.title,
        "format": test.format,
        "description": test.description,
        "passed": not mismatches,
        "expected": test.expected,
        "actual": actual,
        "trace": actual_result.trace,
        "mismatches": mismatches,
    }


def run_all_tests(
    tests: list[TestCase],
    repository: ADSnapshotRepository,
    spn_mappings: dict[str, list[str]],
    category: str | None = None,
) -> list[dict[str, Any]]:
    selected = [test for test in tests if category is None or test.category == category]
    return [run_test(test, repository, spn_mappings) for test in selected]


def print_test_result(result: dict[str, Any], verbose: bool = True) -> None:
    status = "пройден" if result["passed"] else "ошибка"
    print(f"\n[{status}] {result['title']}")
    if verbose or not result["passed"]:
        print(f"id: {result['id']}")
        print(f"описание: {result['description']}")
    actual = result["actual"]
    parsed_format = actual.get("matched_format") or actual.get("detected_format") or "-"
    parsed_object = actual.get("matched_object_id") or "-"
    parsed_reason = actual.get("reason") or "-"
    print(
        "разбор: "
        f"ветка={actual.get('algorithm_branch') or '-'}, "
        f"формат={parsed_format}, "
        f"объект={parsed_object}, "
        f"причина={parsed_reason}"
    )
    if verbose or not result["passed"]:
        print("ожидалось:")
        print(json.dumps(result["expected"], ensure_ascii=False, indent=2))
        print("получилось:")
        print(json.dumps(result["actual"], ensure_ascii=False, indent=2))
    if not result["passed"]:
        # Trace печатаем только на failed-тестах, чтобы видеть, какой шаг
        # алгоритма разошелся с expectation.
        print("расхождения:")
        print(json.dumps(result["mismatches"], ensure_ascii=False, indent=2))
        if result.get("trace"):
            print("trace:")
            print(json.dumps(result["trace"], ensure_ascii=False, indent=2))


def print_summary(results: list[dict[str, Any]]) -> None:
    passed = sum(1 for result in results if result["passed"])
    failed = len(results) - passed
    print(f"\nИтог: пройдено {passed}, ошибок {failed}, всего {len(results)}")
