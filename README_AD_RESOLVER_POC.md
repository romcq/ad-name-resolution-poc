# AD-like Name Resolution PoC

Этот PoC имитирует работу ITDR-логики: берёт имя из условного LDAP/Kerberos-трафика, определяет формат, ищет объект в локальном AD snapshot и показывает, какое поле базы сработало.

PoC не подключается к AD, не делает LDAP Bind, не выполняет Kerberos и не парсит pcap. Это макет алгоритма resolution.

## Файлы

| Файл | Назначение |
|---|---|
| `ad_resolver_poc.py` | Основной Python-движок: CLI, алгоритмы LDAP/Kerberos, загрузка JSON-файлов. |
| `ad_database.json` | База AD-объектов: обычные пользователи, сервисы и corner-case объекты. |
| `ad_test_cases.json` | Тест-кейсы: input, expected status, expected format, expected object, описание. |
| `ad_test_config.json` | Группы тестов и описания разделов. |
| `ad_resolver_test_matrix.md` | Матрица проверок и команды запуска. |

## Запуск

```powershell
cd "D:\My test Codex"
python ad_resolver_poc.py
```

Главное меню:

- `manual` — вручную ввести protocol + login.
- `auto` — проиграть готовые кейсы.
- `database` — показать текущий AD snapshot.
- `exit` — выйти.

В меню работает Tab-автодополнение.

Быстрый прогон всех тестов:

```powershell
python ad_resolver_poc.py --test
```

Подробный отчёт по corner cases:

```powershell
python ad_resolver_poc.py --report --test-group corner
```

## Что показывает результат

В подробном режиме результат показывает:

| Поле | Смысл |
|---|---|
| `status` | `found`, `not_found`, `ambiguous`, `unsupported`, `invalid_input`. |
| `protocol` | LDAP или Kerberos. |
| `input` | Исходный ручной ввод. |
| `simulated_traffic_input` | Только для Kerberos: имитация `AS-REQ` / `TGS-REQ` principal-структуры. |
| `name_format` | Итоговый формат, по которому объект найден. |
| `parsed_input` | Как PoC разобрал вход: формат и имя. |
| `ad_lookup` | По какому полю AD-базы и какому значению выполнялся поиск. |
| `matched_user` / `matched_service` | Найденный объект. |
| `resolved_fields` | Заполненные поля результата из найденного AD-объекта. |
| `matched_candidates` | Кандидаты, если результат `ambiguous`. |

## LDAP-алгоритм

Для LDAP PoC считает, что введённый login — это `BindRequest.name`.

Порядок проверки имитирует AD DS Simple Authentication:

1. `distinguishedName`
2. `userPrincipalName`
3. `generatedUPN`: `sAMAccountName@domainFQDN`
4. `downLevelLogonName`: `DOMAIN\sAMAccountName`
5. `canonicalName`
6. `objectGUID`
7. `displayName`
8. `servicePrincipalName`
9. `MapSPN` — упрощённо через SPN
10. `objectSid`
11. `sIDHistory`
12. `canonicalNameWithLf`

Правила:

- Проверка идёт строго сверху вниз.
- Если найден один объект — `found`.
- Если найдено несколько объектов в рамках одного поля — `ambiguous`.
- Если объект не найден по текущему формату — проверяется следующий формат.
- Если строка совпадает со значением нескольких разных полей, побеждает поле, которое проверяется раньше.

Пример:

`HTTP/userA` может быть:

- `displayName` объекта `displayAsSpn`;
- `servicePrincipalName` объекта `userA`.

Так как `displayName` проверяется раньше `servicePrincipalName`, PoC вернёт `displayAsSpn`.

## Kerberos-алгоритм

Для Kerberos ручной ввод сначала проходит слой симуляции.

### Симуляция входа

| Ручной input | Симулированный трафик |
|---|---|
| `user@domain` | `AS-REQ`, `cname.name-type = 10`, `NT-ENTERPRISE` |
| `DOMAIN\user` | `AS-REQ`, `cname.name-type = 1`, `NT-PRINCIPAL` |
| `service/host` | `TGS-REQ`, `sname.name-type = 2`, `NT-SRV-INST` |
| `userA` | `unsupported` в PoC |

### AS-REQ Client Principal Lookup

Для `NT-ENTERPRISE`:

1. Проверить `userPrincipalName`.
2. Проверить `generatedUPN`.
3. Если доменная часть совпадает с realm, проверить `sAMAccountName`.
4. Проверить `sAMAccountName + "$"`.
5. `CrackNames` не реализован, оставлен как future extension.

Для `NT-PRINCIPAL`:

1. Проверить `sAMAccountName` в контексте realm.
2. Проверить `sAMAccountName + "$"`.
3. Сформировать UPN-вариант и проверить `userPrincipalName` / `generatedUPN`.
4. `CrackNames` не реализован.

### TGS-REQ Server Principal Lookup

Для `NT-SRV-INST`:

1. Собрать `service/host`.
2. Проверить `servicePrincipalName`.
3. Если имя из одного компонента — попробовать `sAMAccountName`.
4. Потом `sAMAccountName + "$"`.

## База AD

Файл: `ad_database.json`.

Структура:

```json
{
  "demo": [],
  "test_extra": []
}
```

- `demo` — базовые объекты.
- `test_extra` — дополнительные объекты для corner cases.
- Полная тестовая база = `demo + test_extra`.

Поля объекта:

- `sAMAccountName`
- `userPrincipalName`
- `distinguishedName`
- `canonicalName`
- `displayName`
- `objectGUID`
- `objectSid`
- `servicePrincipalName`
- `sIDHistory`
- `domainFQDN`
- `domainNetBIOS`
- `object_type`

## Основные объекты базы

| Объект | Тип | Назначение |
|---|---|---|
| `userA` | user | Обычный пользователь `pastukhov.lab`. |
| `userB` | user | Обычный пользователь `domain3.lab`. |
| `10-23-RP-DC-01$` | computer | Сервисный объект DC с SPN `cifs/...` и `HOST/...`. |

## Corner-case объекты

### Generated / implicit UPN

| Объект | Особенность |
|---|---|
| `userImplicit` | `userPrincipalName = null`, generated UPN = `userImplicit@pastukhov.lab`. |
| `userUpnSet` | `sAMAccountName = userUpnSet`, но explicit UPN = `userUpnSetX@pastukhov.lab`. |
| `userImplicitOwner` | Имеет generated UPN `userImplicitOwner@pastukhov.lab`. |
| `userConflict` | Explicit UPN = `userImplicitOwner@pastukhov.lab`, то есть совпадает с generated UPN другого пользователя. |

### Дубли в одном поле

| Объекты | Поле | Значение |
|---|---|---|
| `displayDup1`, `displayDup2` | `displayName` | `User Duplicate` |
| `spnDup1`, `spnDup2` | `servicePrincipalName` | `HTTP/duplicate` |
| `dupUpn1`, `dupUpn2` | `userPrincipalName` | `dup@pastukhov.lab` |
| `sidDup1`, `sidDup2` | `objectSid` | `S-1-5-21-...-3000` |

Ожидаемый результат для таких кейсов — `ambiguous`.

### Значения разных полей пересекаются

| Объект | Поле | Значение совпадает с |
|---|---|---|
| `displayAsUpn` | `displayName = userA@pastukhov.lab` | `userPrincipalName` объекта `userA` |
| `displayAsDn` | `displayName = CN=userA,CN=Users,DC=pastukhov,DC=lab` | `distinguishedName` объекта `userA` |
| `displayAsCanonical` | `displayName = pastukhov.lab/Users/userA` | `canonicalName` объекта `userA` |
| `displayAsGuid` | `displayName = {5c69b042-e0e9-475a-ae37-1751ef9e05e7}` | `objectGUID` объекта `userA` |
| `displayAsSid` | `displayName = S-1-5-21-...-1114` | `objectSid` объекта `userA` |
| `displayAsSpn` | `displayName = HTTP/userA` | `servicePrincipalName` объекта `userA` |

Эти объекты проверяют приоритет порядка LDAP-поиска.

Например:

- `userA@pastukhov.lab` должен найти `userA` по `userPrincipalName`, а не `displayAsUpn` по `displayName`.
- `HTTP/userA` должен найти `displayAsSpn` по `displayName`, потому что `displayName` раньше `servicePrincipalName`.
- SID `userA` должен найти `displayAsSid` по `displayName`, потому что `displayName` раньше `objectSid`.

## Тесты

Файл: `ad_test_cases.json`.

Поля тест-кейса:

| Поле | Смысл |
|---|---|
| `section` | Раздел тестов. |
| `case_id` | Уникальный ID кейса. |
| `protocol` | `ldap` или `kerberos`. |
| `login` | Входная строка. |
| `expected_status` | Ожидаемый статус. |
| `expected_name_format` | Ожидаемый формат. |
| `expected_object` | Ожидаемый `sAMAccountName`. |
| `expected_message` | Для Kerberos: `AS-REQ` или `TGS-REQ`. |
| `expected_traffic` | Проверка полей simulated traffic, например `cname.name-type = 10`. |
| `expected_lookup_field` | Ожидаемое поле AD lookup. |
| `snapshot` | `demo` или `test`. |
| `description` | Человеческое описание кейса. |

## Разделы тестов

| Раздел | Смысл |
|---|---|
| `ldap_basic` | Обычные LDAP-варианты из таблиц. |
| `ldap_negative` | Отрицательные LDAP-сценарии. |
| `ldap_priority` | Приоритет LDAP-форматов и пересечения полей. |
| `ldap_corner` | LDAP corner cases из документа. |
| `kerberos_basic` | Обычные Kerberos-варианты из таблиц. |
| `kerberos_as_req` | AS-REQ Client Principal Lookup. |
| `kerberos_tgs_req` | TGS-REQ Server Principal Lookup. |
| `kerberos_corner` | Kerberos corner cases. |
| `edge` | Дополнительные проверки устойчивости. |

## Группы тестов

Файл: `ad_test_config.json`.

| Группа | Что запускает |
|---|---|
| `ordinary` / `basic` | Обычные LDAP/Kerberos сценарии. |
| `corner` | Corner cases и приоритеты. |
| `negative` | Отрицательные проверки. |
| `edge` | Дополнительные проверки устойчивости. |
| `all` | Все кейсы. |

## Как добавить объект

Открой `ad_database.json` и добавь объект в `test_extra`:

```json
{
  "sAMAccountName": "newUser",
  "userPrincipalName": "newUser@pastukhov.lab",
  "distinguishedName": "CN=newUser,CN=Users,DC=pastukhov,DC=lab",
  "canonicalName": "pastukhov.lab/Users/newUser",
  "displayName": "New User",
  "objectGUID": "00000000-0000-0000-0000-000000009999",
  "objectSid": "S-1-5-21-2845156888-2425353457-3474467337-9999",
  "servicePrincipalName": [],
  "sIDHistory": [],
  "domainFQDN": "pastukhov.lab",
  "domainNetBIOS": "PASTUKHOV",
  "object_type": "user"
}
```

## Как добавить тест

Открой `ad_test_cases.json` и добавь кейс:

```json
{
  "section": "ldap_corner",
  "case_id": "LDAP-CUSTOM-001",
  "protocol": "ldap",
  "login": "newUser@pastukhov.lab",
  "expected_status": "found",
  "expected_name_format": "userPrincipalName",
  "expected_object": "newUser",
  "expected_message": null,
  "expected_traffic": null,
  "expected_lookup_field": "userPrincipalName",
  "snapshot": "test",
  "description": "Проверяем поиск нового пользователя по explicit UPN."
}
```

После этого:

```powershell
python ad_resolver_poc.py --test
```

## Текущее покрытие

Сейчас полный прогон:

```text
75 passed, 0 failed
```

Покрыто:

- LDAP basic formats.
- Kerberos AS-REQ и TGS-REQ simulation.
- generated / implicit UPN.
- explicit UPN vs generated UPN conflict.
- дубли в `displayName`, `SPN`, `UPN`, `SID`.
- пересечение значений разных полей.
- unsupported / invalid / not_found сценарии.
