# AD-like Name Resolution Prototype v2

Прототип проверяет блок AD-like name resolution по статье и согласованным уточнениям: уже разобранное LDAP/Kerberos-событие попадает в resolver, выбирается ветка алгоритма, определяется формат имени и выполняется поиск в локальном AD snapshot.

Это не точная эмуляция одного KDC/DC. Модель ближе к ITDR-продукту: продукт уже имеет snapshot доступных AD-объектов и сопоставляет значения из трафика с этой базой. Поэтому полные идентификаторы могут искаться по всему snapshot, а `realm` / `domain_context` используются как контекст для коротких или неоднозначных имен.

Старый PoC в этой логике не используется. База и тесты ограничены объектами и кейсами из статьи/таблиц; искусственные `ambiguous`/`candidate_object_ids` сценарии убраны.

## Структура

- `run.py` - точка запуска CLI.
- `ad_snapshot.json` - локальный AD snapshot и упрощенные MapSPN mappings.
- `tests.json` - тесты с описанием, входным событием и expected-result.
- `ad_name_resolution/` - router, LDAP resolver, Kerberos resolver, repository, CLI и test runner.

`__pycache__/` и `*.pyc` не входят в проект и исключены через `.gitignore`.

## Модель Поиска

Полные AD-идентификаторы ищутся по всему snapshot:

- `userPrincipalName`
- `distinguishedName`
- `canonicalName`
- `objectGUID`
- `objectSid`
- `servicePrincipalName`
- `sIDHistory`

`realm` / `domain_context` при этом не запрещает поиск в другом домене. Если есть несколько совпадений, локальный домен получает приоритет.

Короткие или относительные имена используют доменный контекст:

- `sAMAccountName`
- `sAMAccountName + "$"`
- generated UPN
- `DOMAIN\user`

`CrackNames` отдельно не реализуется: для PoC считаем, что наличие snapshot по доступным доменам заменяет отдельную попытку поиска в другом доменном контексте.

## Запуск

Из корня проекта:

```powershell
python run.py
```

В меню доступны:

1. Ручной ввод события.
2. Автоматические тесты.
3. Выход.

Ручной LDAP-ввод показывает все варианты из таблицы: `distinguishedName`, `userPrincipalName`, generated UPN, `DOMAIN\user`, `canonicalName`, `objectGUID`, `displayName`, `servicePrincipalName`, MapSPN, `objectSid`, `sIDHistory`, canonicalName с LF.

Ручной Kerberos-ввод работает с полями principal из трафика:

- `AS-REQ / cname / Client Principal Lookup`;
- `TGS-REQ / sname / Server Principal Lookup`;
- `name_type`;
- `name_string[]`;
- `realm`.

`realm` остается отдельным явным полем, как в Kerberos-трафике. Для удобства CLI может предложить default из `name_string[]`, например `userA@pastukhov.lab` -> `PASTUKHOV.LAB`, но resolver получает `realm` как обычное входное поле.

## Тесты

Через меню можно:

- посмотреть список тестов;
- выбрать один тест из списка по номеру;
- запустить все тесты;
- запустить раздел тестов.

Команды для быстрой проверки:

```powershell
python run.py --run-all
python run.py --list-tests
python run.py --run-category ldap_table
```

Если категория не найдена, `--run-category` печатает ошибку и возвращает код `2`.

## Результат

Если объект найден, результат показывает ветку алгоритма, формат имени, поле AD и найденный объект.

Если объект найден в домене, отличном от введенного `realm` / `domain_context`, ручной режим показывает отдельную заметку. Это ожидаемо для ITDR snapshot-модели, когда полное имя найдено в общей базе.

Если объект не найден, но формат удалось определить, результат дополнительно показывает `detected_format`. Например: формат распознан как `userPrincipalName`, но объекта в snapshot нет.

Trace остается техническим пояснением для ручной проверки и failed-тестов. База и тесты пока все равно требуют ручной перепроверки по статье.
