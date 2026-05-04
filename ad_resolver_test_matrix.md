# Матрица проверок AD-like name resolution PoC

Файл описывает проверки для `ad_resolver_poc.py`: сначала базовые варианты из таблиц LDAP/Kerberos, затем corner cases из документа, затем дополнительные проблемные сценарии.

## Файлы PoC

- `ad_resolver_poc.py` — движок resolution, CLI, меню, загрузка данных.
- `ad_database.json` — AD snapshot: базовые объекты в `demo` и дополнительные corner-case объекты в `test_extra`.
- `ad_test_cases.json` — тестовые кейсы: раздел, описание, input, ожидаемый статус/формат/объект.
- `ad_test_config.json` — группы тестов и описания разделов.
- `ad_resolver_test_matrix.md` — человекочитаемая памятка и матрица.

Чтобы добавить пользователя или сервисный объект, редактируй `ad_database.json`.
Чтобы добавить кейс, редактируй `ad_test_cases.json`.
Чтобы добавить новую группу или описание раздела, редактируй `ad_test_config.json`.

## Как запускать

Интерактивный ручной режим:

```powershell
cd "D:\My test Codex"
python ad_resolver_poc.py
```

После запуска скрипт покажет меню:

- `manual` — вручную вводить protocol + login.
- `auto` — проигрывать готовые кейсы.
- `database` — показать расширенный AD snapshot со всеми полями объектов.
- `exit` — выйти.

В меню работает Tab-автодополнение по доступным вариантам. В ручном режиме для login тоже можно нажимать Tab, чтобы подставлять примеры из тестовых кейсов.

В автоматическом режиме можно выбрать группу:

- `ordinary` / `basic` — обычные LDAP/Kerberos сценарии.
- `corner` — corner cases и проверки приоритета.
- `negative` — отрицательные проверки.
- `edge` — дополнительные проверки устойчивости.
- `all` — все проверки.

Или конкретный раздел:

- `ldap_basic`
- `ldap_negative`
- `ldap_priority`
- `ldap_corner`
- `kerberos_basic`
- `kerberos_as_req`
- `kerberos_tgs_req`
- `kerberos_corner`
- `edge`

После выбора автоматического набора можно выбрать формат вывода:

- `detailed` — описание кейса, ожидание и полный фактический разбор.
- `simple` — описание кейса и краткий фактический результат.

В подробном выводе теперь отдельно показываются:

- `parsed_input` — как PoC разобрал вход: формат и имя.
- `ad_lookup` — по какому полю AD-базы и какому значению выполнялся поиск.
- `resolved_fields` — какие поля найденного объекта заполнены в результате.
- `matched_candidates` — список кандидатов для `ambiguous`.

Прогнать все встроенные тесты:

```powershell
python ad_resolver_poc.py --test
```

Прогнать все тесты с печатью каждого `PASS`:

```powershell
python ad_resolver_poc.py --test --verbose
```

Прогнать обычные кейсы с описанием и фактическим разбором:

```powershell
python ad_resolver_poc.py --report --test-group ordinary
```

Прогнать corner cases с описанием и фактическим разбором:

```powershell
python ad_resolver_poc.py --report --test-group corner
```

Прогнать конкретный раздел с описанием и фактическим разбором:

```powershell
python ad_resolver_poc.py --report --test-section ldap_corner
python ad_resolver_poc.py --report --test-section kerberos_corner
```

Показать доступные разделы:

```powershell
python ad_resolver_poc.py --list-tests
```

Прогнать один раздел:

```powershell
python ad_resolver_poc.py --test-section ldap_basic
python ad_resolver_poc.py --test-section ldap_corner
python ad_resolver_poc.py --test-section kerberos_basic
python ad_resolver_poc.py --test-section kerberos_corner
python ad_resolver_poc.py --test-section edge
```

Разделы встроенных тестов:

- `ldap_basic` — обычные LDAP-варианты из таблиц.
- `ldap_negative` — отрицательные LDAP-сценарии.
- `ldap_priority` — приоритет форматов и ambiguity.
- `ldap_corner` — LDAP corner cases из документа.
- `kerberos_basic` — обычные Kerberos-варианты из таблиц.
- `kerberos_as_req` — Kerberos AS-REQ Client Principal Lookup.
- `kerberos_tgs_req` — Kerberos TGS-REQ Server Principal Lookup.
- `kerberos_corner` — Kerberos corner cases из документа.
- `edge` — дополнительные проверки устойчивости.

Группы встроенных тестов:

- `ordinary` / `basic` — обычные LDAP/Kerberos сценарии.
- `corner` — corner cases и проверки приоритета.
- `negative` — отрицательные проверки.
- `edge` — дополнительные проверки устойчивости.
- `all` — все проверки.

Статусы:

- `found` — найден ровно один объект.
- `not_found` — объект не найден.
- `ambiguous` — найдено несколько объектов, выбирать случайный нельзя.
- `unsupported` — формат или ветка пока сознательно не поддержаны PoC.
- `invalid_input` — пустой или некорректный ввод.

Пометки:

- `demo` — проверяется на текущем встроенном snapshot без изменений.
- `needs_fixture` — нужен дополнительный объект в snapshot.
- `future` — проверка важна для продукта, но может быть вне первого PoC.

## LDAP: варианты из таблицы форматов

| ID | Fixture | Input | Что проверяем | Ожидаемый статус | Ожидаемый формат | Ожидаемый объект |
|---|---|---|---|---|---|---|
| LDAP-001 | demo | `userA@pastukhov.lab` | Explicit UPN | `found` | `userPrincipalName` | `userA` |
| LDAP-002 | demo | `userB@domain3.lab` | Explicit UPN во втором домене | `found` | `userPrincipalName` | `userB` |
| LDAP-003 | demo | `PASTUKHOV\userA` | Down-Level Logon Name | `found` | `downLevelLogonName` | `userA` |
| LDAP-004 | demo | `DOMAIN3\userB` | Down-Level Logon Name во втором домене | `found` | `downLevelLogonName` | `userB` |
| LDAP-005 | demo | `CN=userA,CN=Users,DC=pastukhov,DC=lab` | Distinguished Name | `found` | `distinguishedName` | `userA` |
| LDAP-006 | demo | `CN=userB,CN=Users,DC=domain3,DC=lab` | Distinguished Name во втором домене | `found` | `distinguishedName` | `userB` |
| LDAP-007 | demo | `pastukhov.lab/Users/userA` | Canonical Name | `found` | `canonicalName` | `userA` |
| LDAP-008 | demo | `domain3.lab/Users/userB` | Canonical Name во втором домене | `found` | `canonicalName` | `userB` |
| LDAP-009 | demo | `User A` | Display Name | `found` | `displayName` | `userA` |
| LDAP-010 | demo | `User B` | Display Name во втором домене | `found` | `displayName` | `userB` |
| LDAP-011 | demo | `{5c69b042-e0e9-475a-ae37-1751ef9e05e7}` | objectGUID в фигурных скобках | `found` | `objectGUID` | `userA` |
| LDAP-012 | demo | `{36eba909-f454-4695-918b-dcdf33b7cd88}` | objectGUID во втором домене | `found` | `objectGUID` | `userB` |
| LDAP-013 | demo | `5c69b042-e0e9-475a-ae37-1751ef9e05e7` | objectGUID без фигурных скобок | `found` | `objectGUID` | `userA` |
| LDAP-014 | demo | `HTTP/userA` | servicePrincipalName пользователя | `found` | `servicePrincipalName` | `userA` |
| LDAP-015 | demo | `HTTP/userB` | servicePrincipalName пользователя во втором домене | `found` | `servicePrincipalName` | `userB` |
| LDAP-016 | demo | `cifs/10-23-RP-DC-01.pastukhov.lab` | servicePrincipalName компьютера | `found` | `servicePrincipalName` | `10-23-RP-DC-01$` |
| LDAP-017 | demo | `HOST/10-23-RP-DC-01.pastukhov.lab` | HOST SPN компьютера | `found` | `servicePrincipalName` или `MapSPN` | `10-23-RP-DC-01$` |
| LDAP-018 | demo | `S-1-5-21-2845156888-2425353457-3474467337-1114` | objectSid | `found` | `objectSid` | `userA` |
| LDAP-019 | demo | `S-1-5-21-3677553567-317466416-2570716728-1106` | objectSid во втором домене | `found` | `objectSid` | `userB` |
| LDAP-020 | future | `S-1-5-21-...-OLD` | sIDHistory | `found` | `sIDHistory` | объект с таким SID history |
| LDAP-021 | demo | `pastukhov.lab/Domain Controllers\n10-23-RP-DC-01` | canonicalName с LF вместо последнего `/` | `found` | `canonicalNameWithLf` | `10-23-RP-DC-01$` |

## LDAP: отрицательные и приоритетные проверки

| ID | Fixture | Input | Что проверяем | Ожидаемый статус | Ожидаемый формат | Ожидаемый объект |
|---|---|---|---|---|---|---|
| LDAP-101 | demo | `userA` | Просто sAMAccountName для LDAP в текущем PoC не входит в обязательный порядок | `not_found` | — | — |
| LDAP-102 | demo | `UNKNOWN\userA` | Неизвестный NetBIOS-домен | `not_found` | — | — |
| LDAP-103 | demo | `PASTUKHOV\missing` | Домен известен, пользователя нет | `not_found` | — | — |
| LDAP-104 | demo | `not-a-guid` | Невалидный GUID | `not_found` | — | — |
| LDAP-105 | demo | `S-1-abc` | Невалидный SID | `not_found` | — | — |
| LDAP-106 | demo | `` | Пустой ввод | `invalid_input` | — | — |
| LDAP-107 | needs_fixture | `userA@pastukhov.lab` | Эта же строка задана как `displayName` другого объекта; должен победить UPN | `found` | `userPrincipalName` | `userA` |
| LDAP-108 | needs_fixture | `CN=userA,CN=Users,DC=pastukhov,DC=lab` | Эта же строка задана как `displayName`; должен победить DN | `found` | `distinguishedName` | `userA` |
| LDAP-109 | needs_fixture | `pastukhov.lab/Users/userA` | Эта же строка задана как `displayName`; должен победить canonicalName | `found` | `canonicalName` | `userA` |
| LDAP-110 | needs_fixture | `HTTP/userA` | Эта же строка задана как `displayName`; должен победить displayName или SPN? По текущему порядку displayName раньше SPN, значит displayName | `found` | `displayName` | объект с таким displayName |
| LDAP-111 | needs_fixture | `User Duplicate` | Два пользователя с одинаковым displayName | `ambiguous` | `displayName` | — |
| LDAP-112 | needs_fixture | `HTTP/duplicate` | Два объекта с одинаковым SPN | `ambiguous` | `servicePrincipalName` | — |
| LDAP-113 | needs_fixture | `dup@pastukhov.lab` | Два объекта с одинаковым explicit UPN | `ambiguous` | `userPrincipalName` | — |

## LDAP: corner cases из документа

| ID | Fixture | Input | Что проверяем | Ожидаемый статус | Ожидаемый формат | Ожидаемый объект |
|---|---|---|---|---|---|---|
| LDAP-C01 | needs_fixture | `userImplicit@pastukhov.lab` | `userPrincipalName` не задан, срабатывает generated/implicit UPN | `found` | `generatedUPN` | `userImplicit` |
| LDAP-C02 | needs_fixture | `userUpnSet@pastukhov.lab` | `userPrincipalName` задан как другой UPN, но generated UPN всё равно проверяется для LDAP | `found` | `generatedUPN` или `sAMAccountName` по выбранной модели | `userUpnSet` |
| LDAP-C03 | needs_fixture | `userUpnSetX@pastukhov.lab` | Явный UPN после ручной замены | `found` | `userPrincipalName` | `userUpnSet` |
| LDAP-C04 | needs_fixture | `userImplicitOwner@pastukhov.lab` | Explicit UPN одного пользователя совпал с generated UPN другого; explicit UPN должен победить | `found` | `userPrincipalName` | `userConflict` |
| LDAP-C05 | needs_fixture | `userTrust@pastukhov.lab` | Два леса/trust, конфликтующий UPN; приоритет локального домена | `found` | `userPrincipalName` | локальный `userTrust` |
| LDAP-C06 | needs_fixture | `User Same Display` | Совпадение displayName у двух пользователей | `ambiguous` | `displayName` | — |
| LDAP-C07 | needs_fixture | `userA` | `displayName = sAMAccountName`; если sAMAccountName не проверяется раньше, победит displayName | `found` | `displayName` | объект с displayName `userA` |
| LDAP-C08 | needs_fixture | `userA@pastukhov.lab` | `displayName = userPrincipalName`; должен победить UPN | `found` | `userPrincipalName` | `userA` |
| LDAP-C09 | needs_fixture | `PASTUKHOV\userA` | `displayName = DOMAIN\user`; должен победить Down-Level | `found` | `downLevelLogonName` | `userA` |
| LDAP-C10 | needs_fixture | `CN=userA,CN=Users,DC=pastukhov,DC=lab` | `displayName = DN`; должен победить DN | `found` | `distinguishedName` | `userA` |
| LDAP-C11 | needs_fixture | `pastukhov.lab/Users/userA` | `displayName = canonicalName`; должен победить canonicalName | `found` | `canonicalName` | `userA` |
| LDAP-C12 | needs_fixture | `{5c69b042-e0e9-475a-ae37-1751ef9e05e7}` | `displayName = objectGUID`; должен победить objectGUID | `found` | `objectGUID` | `userA` |
| LDAP-C13 | needs_fixture | `HTTP/userA` | `displayName = servicePrincipalName`; в документе выбран displayName, потому что displayName раньше SPN | `found` | `displayName` | объект с displayName `HTTP/userA` |
| LDAP-C14 | needs_fixture | `S-1-5-21-2845156888-2425353457-3474467337-1114` | `displayName = objectSid`; из-за порядка displayName раньше objectSid | `found` | `displayName` | объект с таким displayName |

## Kerberos: варианты из таблицы форматов

| ID | Fixture | Input | Симуляция трафика | Что проверяем | Ожидаемый статус | Ожидаемый формат | Ожидаемый объект |
|---|---|---|---|---|---|---|---|
| KRB-001 | demo | `userA@pastukhov.lab` | `AS-REQ cname.name-type=10` | UPN как NT-ENTERPRISE | `found` | `NT-ENTERPRISE/userPrincipalName` | `userA` |
| KRB-002 | demo | `userB@domain3.lab` | `AS-REQ cname.name-type=10` | UPN во втором домене | `found` | `NT-ENTERPRISE/userPrincipalName` | `userB` |
| KRB-003 | demo | `PASTUKHOV\userA` | `AS-REQ cname.name-type=1` | Down-Level как NT-PRINCIPAL | `found` | `NT-PRINCIPAL/sAMAccountName` | `userA` |
| KRB-004 | demo | `DOMAIN3\userB` | `AS-REQ cname.name-type=1` | Down-Level во втором домене | `found` | `NT-PRINCIPAL/sAMAccountName` | `userB` |
| KRB-005 | demo | `cifs/10-23-RP-DC-01.pastukhov.lab` | `TGS-REQ sname.name-type=2` | Service principal lookup | `found` | `NT-SRV-INST/servicePrincipalName` | `10-23-RP-DC-01$` |
| KRB-006 | demo | `HOST/10-23-RP-DC-01.pastukhov.lab` | `TGS-REQ sname.name-type=2` | HOST service principal lookup | `found` | `NT-SRV-INST/servicePrincipalName` | `10-23-RP-DC-01$` |
| KRB-007 | demo | `userA` | — | Просто SAM Account Name как ручной Kerberos input | `unsupported` | — | — |
| KRB-008 | demo | `CN=userA,CN=Users,DC=pastukhov,DC=lab` | — | DN в Kerberos не принимается | `unsupported` или `not_found` | — | — |
| KRB-009 | demo | `pastukhov.lab/Users/userA` | `TGS-REQ sname.name-type=2` по грубой симуляции из-за `/` | Canonical Name не должен считаться пользовательским Kerberos login | `not_found` | — | — |
| KRB-010 | demo | `User A` | — | Display Name в Kerberos не принимается | `unsupported` | — | — |
| KRB-011 | demo | `{5c69b042-e0e9-475a-ae37-1751ef9e05e7}` | — | objectGUID в Kerberos не принимается | `unsupported` | — | — |
| KRB-012 | demo | `S-1-5-21-2845156888-2425353457-3474467337-1114` | — | objectSID в Kerberos не принимается | `unsupported` | — | — |
| KRB-013 | demo | `HTTP/userA` | `TGS-REQ sname.name-type=2` | SPN пользователя как сервисный principal | `found` | `NT-SRV-INST/servicePrincipalName` | `userA` |

## Kerberos: AS-REQ Client Principal Lookup

| ID | Fixture | Input | Что проверяем | Ожидаемый статус | Ожидаемый формат | Ожидаемый объект |
|---|---|---|---|---|---|---|
| KRB-AS-001 | demo | `userA@pastukhov.lab` | NT-ENTERPRISE сначала ищет explicit UPN | `found` | `NT-ENTERPRISE/userPrincipalName` | `userA` |
| KRB-AS-002 | needs_fixture | `userImplicit@pastukhov.lab` | NT-ENTERPRISE generated UPN, если explicit UPN отсутствует | `found` | `NT-ENTERPRISE/generatedUPN` | `userImplicit` |
| KRB-AS-003 | needs_fixture | `machine@pastukhov.lab` | NT-ENTERPRISE fallback в `sAMAccountName + "$"` | `found` | `NT-ENTERPRISE/sAMAccountName+$` | `machine$` |
| KRB-AS-004 | demo | `PASTUKHOV\userA` | NT-PRINCIPAL сначала ищет sAMAccountName в realm | `found` | `NT-PRINCIPAL/sAMAccountName` | `userA` |
| KRB-AS-005 | demo | `PASTUKHOV\10-23-RP-DC-01` | NT-PRINCIPAL fallback в `sAMAccountName + "$"` | `found` | `NT-PRINCIPAL/sAMAccountName+$` | `10-23-RP-DC-01$` |
| KRB-AS-006 | needs_fixture | `PASTUKHOV\userOnlyUpn` | NT-PRINCIPAL fallback в UPN/generated UPN | `found` | `NT-PRINCIPAL/userPrincipalName` или `NT-PRINCIPAL/generatedUPN` | `userOnlyUpn` |
| KRB-AS-007 | demo | `UNKNOWN\userA` | Неизвестный NetBIOS-домен на этапе симуляции | `not_found` | — | — |
| KRB-AS-008 | demo | `userA@unknown.lab` | Realm есть, домена/объекта нет | `not_found` | — | — |
| KRB-AS-009 | needs_fixture | `duplicate@pastukhov.lab` | Несколько объектов с одинаковым UPN | `ambiguous` | `NT-ENTERPRISE/userPrincipalName` | — |

## Kerberos: TGS-REQ Server Principal Lookup

| ID | Fixture | Input | Что проверяем | Ожидаемый статус | Ожидаемый формат | Ожидаемый объект |
|---|---|---|---|---|---|---|
| KRB-TGS-001 | demo | `cifs/10-23-RP-DC-01.pastukhov.lab` | SPN компьютера | `found` | `NT-SRV-INST/servicePrincipalName` | `10-23-RP-DC-01$` |
| KRB-TGS-002 | demo | `HOST/10-23-RP-DC-01.pastukhov.lab` | HOST SPN компьютера | `found` | `NT-SRV-INST/servicePrincipalName` | `10-23-RP-DC-01$` |
| KRB-TGS-003 | demo | `HTTP/userA` | SPN на пользовательском объекте | `found` | `NT-SRV-INST/servicePrincipalName` | `userA` |
| KRB-TGS-004 | demo | `cifs/missing.pastukhov.lab` | Сервис не найден | `not_found` | — | — |
| KRB-TGS-005 | needs_fixture | `HTTP/duplicate` | Два объекта с одинаковым SPN | `ambiguous` | `NT-SRV-INST/servicePrincipalName` | — |
| KRB-TGS-006 | future | `krbtgt/PASTUKHOV.LAB` | Специальный случай krbtgt | `found` | `NT-SRV-INST/krbtgt` | `krbtgt` |
| KRB-TGS-007 | future | `service/host@REALM` | Сервисное имя с MIT realm после `@` | `found` или `not_found` по fixture | `servicePrincipalName` | объект SPN |

## Kerberos: corner cases из документа

| ID | Fixture | Input | Что проверяем | Ожидаемый статус | Ожидаемый формат | Ожидаемый объект |
|---|---|---|---|---|---|---|
| KRB-C01 | needs_fixture | `userImplicit@pastukhov.lab` | `userPrincipalName` не задан, срабатывает implicit/generated UPN | `found` | `NT-ENTERPRISE/generatedUPN` | `userImplicit` |
| KRB-C02 | needs_fixture | `userUpnSet@pastukhov.lab` | В документе KDC продолжает разрешать implicit UPN при заданном другом explicit UPN | `found` | `NT-ENTERPRISE/generatedUPN` или fallback | `userUpnSet` |
| KRB-C03 | needs_fixture | `userUpnSetX@pastukhov.lab` | Явный UPN после ручной замены | `found` | `NT-ENTERPRISE/userPrincipalName` | `userUpnSet` |
| KRB-C04 | needs_fixture | `userImplicitOwner@pastukhov.lab` | Explicit UPN одного пользователя совпал с implicit UPN другого; explicit UPN должен победить | `found` | `NT-ENTERPRISE/userPrincipalName` | `userConflict` |
| KRB-C05 | future | `userTrust@pastukhov.lab` | Два леса/trust, конфликтующий UPN; приоритет локального домена | `found` | `NT-ENTERPRISE/userPrincipalName` | локальный `userTrust` |
| KRB-C06 | demo | `DOMAIN3\userA` | Realm второго домена, имя существует только в первом | `not_found` | — | — |
| KRB-C07 | needs_fixture | `PASTUKHOV\duplicate` | Несколько объектов с одинаковым sAMAccountName в одном realm | `ambiguous` | `NT-PRINCIPAL/sAMAccountName` | — |
| KRB-C08 | future | `service/host` | Нет домена в host; realm не удалось определить | `not_found` или `unsupported` | — | — |

## Дополнительные проверки устойчивости

| ID | Fixture | Protocol | Input | Что проверяем | Ожидаемый статус |
|---|---|---|---|---|---|
| EDGE-001 | demo | LDAP | ` USER A ` | Trim пробелов вокруг ввода | `found` |
| EDGE-002 | demo | LDAP | `USERA@PASTUKHOV.LAB` | Case-insensitive UPN | `found` |
| EDGE-003 | demo | LDAP | `pastukhov\USERA` | Case-insensitive NetBIOS и sAMAccountName | `found` |
| EDGE-004 | demo | LDAP | `http/usera` | Case-insensitive SPN | `found` |
| EDGE-005 | demo | LDAP | `CN=userA, CN=Users, DC=pastukhov, DC=lab` | DN с пробелами после запятых; текущий PoC может не нормализовать | `not_found` в PoC, `found` в future |
| EDGE-006 | future | LDAP | `CN=user\,A,CN=Users,DC=pastukhov,DC=lab` | DN с экранированной запятой | `found` |
| EDGE-007 | future | LDAP | `CN= userA,CN=Users,DC=pastukhov,DC=lab` | DN с экранируемым/значимым начальным пробелом | зависит от fixture |
| EDGE-008 | demo | LDAP | `{5C69B042-E0E9-475A-AE37-1751EF9E05E7}` | Case-insensitive GUID | `found` |
| EDGE-009 | demo | LDAP | `5c69b042e0e9475aae371751ef9e05e7` | GUID без dashed-формата | `not_found` |
| EDGE-010 | demo | Kerberos | `USERA@PASTUKHOV.LAB` | Case-insensitive UPN при Kerberos simulation | `found` |
| EDGE-011 | demo | Kerberos | `pastukhov\USERA` | Case-insensitive NetBIOS и sAMAccountName | `found` |
| EDGE-012 | demo | Kerberos | `CIFS/10-23-rp-dc-01.PASTUKHOV.LAB` | Case-insensitive SPN | `found` |
| EDGE-013 | demo | Kerberos | `/host` | Некорректный service principal | `invalid_input` |
| EDGE-014 | demo | Kerberos | `service/` | Некорректный service principal | `invalid_input` |
| EDGE-015 | demo | CLI | `radius` | Неподдержанный protocol | `invalid_input` |

## Что стоит добавить в fixture-набор следующим шагом

1. `userImplicit`: `sAMAccountName=userImplicit`, `userPrincipalName=None`, домен `pastukhov.lab`.
2. `userUpnSet`: `sAMAccountName=userUpnSet`, `userPrincipalName=userUpnSetX@pastukhov.lab`.
3. `userImplicitOwner`: `sAMAccountName=userImplicitOwner`, `userPrincipalName=None`.
4. `userConflict`: `sAMAccountName=userConflict`, `userPrincipalName=userImplicitOwner@pastukhov.lab`.
5. Два объекта с одинаковым `displayName`.
6. Два объекта с одинаковым `servicePrincipalName`.
7. Объект с заполненным `sIDHistory`.
8. Компьютер `machine$`, чтобы отдельно проверить fallback `sAMAccountName + "$"`.
9. Объект `krbtgt`, если понадобится моделировать специальный Kerberos TGS-case.

## Минимальный smoke-набор для ручной проверки текущего PoC

```text
ldap
userA@pastukhov.lab

ldap
PASTUKHOV\userA

ldap
CN=userA,CN=Users,DC=pastukhov,DC=lab

ldap
pastukhov.lab/Users/userA

ldap
{5c69b042-e0e9-475a-ae37-1751ef9e05e7}

ldap
S-1-5-21-2845156888-2425353457-3474467337-1114

ldap
HTTP/userA

kerberos
userA@pastukhov.lab

kerberos
PASTUKHOV\userA

kerberos
cifs/10-23-RP-DC-01.pastukhov.lab

kerberos
userA
```
