# AD-like Name Resolution Prototype v2

Новый прототип моделирует этап name resolution: уже разобранное LDAP/Kerberos-событие выбирает ветку алгоритма, проходит проверки по правилам статьи и сопоставляется с локальным AD snapshot.

## Структура

- `run.py` - точка запуска CLI.
- `ad_snapshot.json` - локальная база AD-объектов и упрощенные MapSPN-маппинги.
- `tests.json` - тестовые события, описания кейсов и expected-результаты.
- `ad_name_resolution/` - код resolver, LDAP/Kerberos lookup, repository, CLI и test runner.
- `__pycache__/` и `*.pyc` не входят в проект и исключены через `.gitignore`.

## Проверки

Из папки проекта:

```powershell
cd "D:\My test Codex\ad_name_resolution_v2"
python run.py --run-all
```

Один тест:

```powershell
python run.py --run-test ldap_upn_basic
```

Exit code для одного теста: `0`, если тест прошел; `1`, если тест упал; `2`, если test id не найден.

Раздел тестов:

```powershell
python run.py --run-category ldap_corner
```

Если категории нет в `tests.json`, команда печатает `Тесты для категории не найдены: <category>` и возвращает код `2`.

Ручной режим:

```powershell
python run.py --manual
```

При неуспешном resolution ручной режим показывает краткий итог, stable JSON result, человекочитаемое пояснение и технический trace.

## Реализовано

- LDAP Simple Bind: порядок AD DS Simple Authentication, включая DN, UPN/generated UPN, down-level logon name, canonicalName, GUID, displayName, SPN, MapSPN, SID, sIDHistory и canonicalName с LF.
- Kerberos AS-REQ: `NT-ENTERPRISE` и `NT-PRINCIPAL` для Client Principal Lookup.
- Kerberos TGS-REQ: `NT-PRINCIPAL`, `NT-SRV-INST`, `NT-SRV-HST`, `NT-ENTERPRISE` для Server Principal Lookup, включая `krbtgt` special case и SPN-check для fallback.
- Stable JSON result не возвращает старый `ambiguous/candidate_object_ids` слой. Для нескольких совпадений используется `resolved=false` и `reason=not_unique`.

## Ограничения

- Реальный pcap/ASN.1/LDAP decoder не реализован: вход уже должен быть разобранным событием.
- `CrackNames` не реализован полностью и явно отмечается в результате, если алгоритм доходит до этого места.
- `MapSPN` реализован упрощенно через локальный словарь `spn_mappings`.
- AD snapshot является JSON-моделью, а не настоящим каталогом AD.
