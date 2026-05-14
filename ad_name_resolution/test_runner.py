"""Loading, running and printing JSON-defined resolver tests."""

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
    description: str
    input: dict[str, Any]
    expected: dict[str, Any]
    snapshot_object_ids: list[str] | None = None


def load_tests(path: str | Path) -> list[TestCase]:
    with Path(path).open("r", encoding="utf-8") as file:
        raw = json.load(file)
    scenarios = raw.get("snapshot_scenarios", {})
    cases = []
    for item in raw["tests"]:
        scenario_name = item.get("snapshot")
        snapshot_object_ids = item.get("snapshot_object_ids")
        if scenario_name:
            if scenario_name not in scenarios:
                raise ValueError(f"Unknown snapshot scenario for test {item['id']}: {scenario_name}")
            snapshot_object_ids = scenarios[scenario_name]
        cases.append(
            TestCase(
                id=item["id"],
                category=item.get("category", "uncategorized"),
                description=item["description"],
                input=item["input"],
                expected=item["expected"],
                snapshot_object_ids=list(snapshot_object_ids) if snapshot_object_ids else None,
            )
        )
    return cases


def list_tests(tests: list[TestCase]) -> None:
    for index, test in enumerate(tests, 1):
        print(f"{index:02d}. [{test.category}] {test.description}")


def run_test(
    test: TestCase,
    repository: ADSnapshotRepository,
    spn_mappings: dict[str, list[str]],
) -> dict[str, Any]:
    if test.snapshot_object_ids is not None:
        # Часть кейсов статьи специально добавляет пользователей, которые перекрывают
        # другой формат имени. Поэтому тест может запускаться на своем сценарии snapshot.
        repository = repository.subset_by_ids(test.snapshot_object_ids)
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
    status = "passed" if result["passed"] else "failed"
    print(f"\n[{status}] {result['id']} - {result['description']}")
    actual = result["actual"]
    parsed_format = actual.get("matched_format") or actual.get("detected_format") or "-"
    parsed_object = actual.get("matched_object_id") or "-"
    parsed_reason = actual.get("reason") or "-"
    print(
        "parsed: "
        f"branch={actual.get('algorithm_branch') or '-'}, "
        f"format={parsed_format}, "
        f"object={parsed_object}, "
        f"reason={parsed_reason}"
    )
    if verbose or not result["passed"]:
        print("expected:")
        print(json.dumps(result["expected"], ensure_ascii=False, indent=2))
        print("actual:")
        print(json.dumps(result["actual"], ensure_ascii=False, indent=2))
    if not result["passed"]:
        # Trace печатаем только на failed-тестах, чтобы видеть, какой шаг
        # алгоритма разошелся с expectation.
        print("mismatches:")
        print(json.dumps(result["mismatches"], ensure_ascii=False, indent=2))
        if result.get("trace"):
            print("trace:")
            print(json.dumps(result["trace"], ensure_ascii=False, indent=2))


def print_summary(results: list[dict[str, Any]]) -> None:
    passed = sum(1 for result in results if result["passed"])
    failed = len(results) - passed
    print(f"\nSummary: {passed} passed, {failed} failed, {len(results)} total")
