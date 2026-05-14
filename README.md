# AD-like Name Resolution Prototype

Прототип демонстрирует блок AD-like name resolution для ITDR-сценария: на вход приходит уже разобранное LDAP или Kerberos-событие, resolver определяет формат имени, ищет объект в локальном AD snapshot и возвращает результат сопоставления.

Проект не подключается к реальному AD, не выполняет LDAP Bind/Kerberos-обмен и не парсит pcap. Он проверяет именно алгоритм разбора имени и поиска объекта по данным, которые в реальной системе пришли бы из сетевого парсера.

## Структура

- `run.py` - точка запуска CLI.
- `ad_snapshot.json` - локальный AD snapshot: пользователи, сервисные объекты, домены, SPN mappings.
- `tests.json` - автоматические проверки по таблицам и алгоритмам из статьи.
- `ad_name_resolution/resolver.py` - верхний роутер LDAP/Kerberos.
- `ad_name_resolution/ldap_resolver.py` - порядок LDAP Simple Authentication.
- `ad_name_resolution/kerberos_resolver.py` - Client Principal Lookup и Server Principal Lookup.
- `ad_name_resolution/repository.py` - поиск объектов по полям snapshot.
- `ad_name_resolution/cli.py` - ручной режим, меню и печать результата.
- `ad_name_resolution/test_runner.py` - запуск JSON-тестов.

## LDAP

Для LDAP прототип работает с полем:

```text
LDAPMessage -> protocolOp: bindRequest -> bindRequest -> name
```

Порядок проверок повторяет LDAP Simple Authentication:

1. `distinguishedName`
2. `userPrincipalName` / generated UPN
3. `DOMAIN\sAMAccountName`
4. `canonicalName`
5. `objectGUID`
6. `displayName`
7. `servicePrincipalName`
8. `MapSPN`
9. `objectSid`
10. `sIDHistory`
11. `canonicalName` с заменой последнего `/` на `\n`

Generated UPN проверяется после явного `userPrincipalName`. То есть сначала ищется точное значение `userPrincipalName`, а если его нет, строка вида `name@domain` может быть сопоставлена как:

```text
sAMAccountName = name
domainFQDN = domain
```

Если одно и то же значение совпадает с явным `userPrincipalName` одного объекта и generated UPN другого, побеждает явный `userPrincipalName`.

## Kerberos

Для Kerberos прототип принимает поля уже разобранного principal:

- `message_type`: `AS-REQ` или `TGS-REQ`;
- `cname` для `AS-REQ`;
- `sname` для `TGS-REQ`;
- `name_type`;
- `name_string[]`;
- `realm`.

Логика выбора ветки:

```text
AS-REQ  -> cname -> Client Principal Lookup
TGS-REQ -> sname -> Server Principal Lookup
```

Внутри выбранной ветки учитывается `name_type`:

- `1` - `KRB5-NT-PRINCIPAL`
- `2` - `KRB5-NT-SRV-INST`
- `3` - `KRB5-NT-SRV-HST`
- `10` - `KRB5-NT-ENTERPRISE-PRINCIPAL`

`realm` остается отдельным входным полем, как в Kerberos-трафике. CLI может предложить значение по умолчанию, если его можно вывести из введенного имени, но resolver получает `realm` явно.

## AD Snapshot

Snapshot хранится в `ad_snapshot.json`. У объекта есть основные идентификаторы, которые участвуют в проверках:

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

В snapshot включены базовые пользователи `userA`, `userB`, сервисный объект DC, а также corner-объекты из статьи: implicit/generated UPN, explicit UPN priority, одинаковый UPN в разных доменах, DN со спецсимволами и пересечения `displayName` с другими форматами.

## Тесты

Тесты лежат в `tests.json`. Некоторые проверки используют свой `snapshot`-сценарий: это нужно потому, что corner-объекты из статьи могут намеренно менять результат другого формата. Например, пользователь с `displayName = HTTP/userA` должен проверяться отдельно от базового теста `servicePrincipalName = HTTP/userA`.

Основные разделы тестов:

- `ldap_table`
- `ldap_algorithm`
- `ldap_dn_special`
- `ldap_corner`
- `kerberos_client_lookup`
- `kerberos_server_lookup`

## Запуск

Интерактивный режим:

```powershell
python run.py
```

Все тесты:

```powershell
python run.py --run-all
```

Список тестов:

```powershell
python run.py --list-tests
```

Раздел тестов:

```powershell
python run.py --run-category ldap_corner
```

В ручном режиме можно выбрать LDAP или Kerberos, ввести поля события и посмотреть краткий итог, JSON-результат и технический trace проверок.
