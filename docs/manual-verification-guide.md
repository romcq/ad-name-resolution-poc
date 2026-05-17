# Ручная проверка и сравнение с itdr_develop

Документ нужен как рабочая шпаргалка: что сейчас делает архив itdr_develop, чем это отличается от текущего прототипа, как руками прогнать LDAP/Kerberos и какие спорные случаи отдельно смотреть.

## Что найдено в itdr_develop

Основные точки, где происходит разбор имени:

- itdr-develop-unpacked/itdr-develop/src/Itdr.Applications.ActiveDetection.Domain/UseCases/Analysis/Entities/AnalyzeLdapPrincipal.cs - берет LDAP username из уже разобранного payload и передает его в LDAP parser.
- itdr-develop-unpacked/itdr-develop/src/Itdr.Domains.Identification.Ldap/LdapUserNameParser.cs - определяет формат LDAP-имени.
- itdr-develop-unpacked/itdr-develop/src/Itdr.Applications.ActiveDetection.Domain/UseCases/Analysis/Entities/AnalyzeKerberosPrincipalExchange.cs - берет Kerberos client principal из payload и резолвит его как пользователя.
- itdr-develop-unpacked/itdr-develop/src/Itdr.Applications.ActiveDetection.Domain/UseCases/KerberosResourceInspector.cs - отдельно разбирает service principal как ресурс.
- itdr-develop-unpacked/itdr-develop/src/Itdr.Domains.Identification.Kerberos/KerberosPrincipalNameExtensions.cs - переводит Kerberos name-type + components в внутренний IdentityDescription.
- itdr-develop-unpacked/itdr-develop/src/Itdr.Domains.Identification.Adapters.Redis/RedisIdentityContext.cs - ищет разобранное имя в user catalog/Redis.
- itdr-develop-unpacked/itdr-develop/src/Itdr.Common.ActiveDirectory.Abstractions/UserNameCoder.cs - общий parser для UPN и down-level имени.
- itdr-develop-unpacked/itdr-develop/src/Itdr.Common.ActiveDirectory.Abstractions/SemanticServicePrincipalNameCoder.cs - parser SPN-строки вида service/host[:port][/serviceName].

### LDAP в itdr_develop

Текущий LDAP-разбор в архиве сильно уже, чем алгоритм из статьи.

Порядок в LdapUserNameParser:

1. Попробовать userPrincipalName, то есть строку с ровно одним @.
2. Если не получилось - попробовать down-level имя DOMAIN\account, то есть строку с ровно одним обратным слешем.
3. Если в строке нет ни @, ни обратного слеша:
   - для Simple Bind вернуть DisplayName;
   - для SASL Bind вернуть SamAccountName.
4. Если строка похожа на испорченный UPN/down-level, например содержит несколько разделителей, parsing завершается ошибкой.

Важный нюанс поиска в Redis:

- userPrincipalName ищется сначала как явный userPrincipalName, а если не найден - как generated/implicit UPN: sAMAccountName@domain.
- down-level имя сначала переводит NetBIOS-домен в DNS-домен, потом ищет sAMAccountName внутри этого домена.
- DisplayName, если начинается с CN=, сначала пробуется как distinguishedName, и только потом как обычный displayName.

То есть DN в Simple LDAP может иногда разрешиться, но не потому что parser распознал формат distinguishedName, а потому что строка попала в ветку DisplayName, а поиск потом сделал fallback на DN.

### Kerberos в itdr_develop

Kerberos-разбор в архиве тоже уже, чем наш прототип по статье.

В KerberosPrincipalNameExtensions логика такая:

- KrbNTUnknown и KrbNTPrincipal: взять первый компонент как sAMAccountName; если компонентов больше одного и это не well-known имя - вернуть unsupported.
- KrbNTSrvInst: поддерживаются только well-known service account names. Если первый компонент не well-known, это unsupported.
- KrbNTEnterprise, KrbNTMSPrincipal, KrbNTMSPrincipalAndId: ожидается один компонент. Его пробуют как UPN, потом как down-level, потом как sAMAccountName, если разделителей нет.
- KrbNTX500Principal и KrbNTEntPrincipalAndId: явно оставлены как unsupported/TODO.

Отдельно: AnalyzeKerberosPrincipalExchange в основном разбирает именно client principal (ClientName). Service principal разбирается другим путем, через KerberosResourceInspector.

## Спецсимволы: архив против прототипа

| Место | itdr_develop | Текущий прототип |
|---|---|---|
| UPN | Проверяется только структура: строка не пустая, ровно один @, обе части не пустые. Остальные символы специально не валидируются. | То же базовое правило: ровно один @, обе части не пустые. После этого есть явный UPN lookup и generated UPN lookup. |
| Down-level | Проверяется только структура: строка не пустая, ровно один обратный слеш, обе части не пустые. | То же базовое правило. Потом поиск по domainNetBIOS + sAMAccountName. |
| DN | LDAP parser архива не имеет отдельной DN-ветки. В Simple Bind DN попадает как DisplayName, а Redis lookup может сначала попробовать distinguishedName, если строка начинается с CN=. | DN - первый шаг LDAP-алгоритма. Есть разбор escaped comma, чтобы CN=user\,A,... не разрезался как два RDN. Поиск при этом точный: строка должна совпасть с distinguishedName в snapshot. |
| DN-спецсимволы | Нет отдельной DN-нормализации/LDAP escaping parser в LDAP-ветке. | Есть тесты на DN со спецсимволами: запятая, плюс, кавычки, обратный слеш, угловые скобки, точка с запятой, равно, slash, ведущий #. |
| SPN | Есть общий SemanticServicePrincipalNameCoder, но LDAP identity parser не проверяет servicePrincipalName как формат имени. Kerberos KrbNTSrvInst поддержан только ограниченно, через well-known account names. | LDAP проверяет servicePrincipalName и упрощенный MapSPN. Kerberos TGS-REQ проверяет server principal по веткам из статьи. |
| Несколько совпадений | В некоторых местах архив выбирает один результат или пытается выбрать по домену. Публичного not_unique слоя как в прототипе там нет. | Прототип возвращает resolved=false, reason=not_unique, но candidate ids не публикует в stable JSON. |

Главное отличие: архив сейчас выглядит как рабочая, но ограниченная реализация. Прототип сделан как проверка алгоритма из статьи: он специально шире и показывает порядок LDAP/Kerberos lookup шагов.

## Как руками проверить прототип

### Подготовка

1. Открой PowerShell.
2. Перейди в папку проекта:

~~~powershell
cd "D:\My test Codex"
~~~

3. Запусти интерактивный режим:

~~~powershell
python run.py
~~~

4. Для быстрой проверки всех автоматических кейсов можно отдельно выполнить:

~~~powershell
python run.py --run-all
~~~

5. Для просмотра списка тестов:

~~~powershell
python run.py --list-tests
~~~

6. Для запуска раздела:

~~~powershell
python run.py --run-category ldap_table
python run.py --run-category ldap_dn_special
python run.py --run-category ldap_corner
python run.py --run-category kerberos_client_lookup
python run.py --run-category kerberos_server_lookup
~~~

В интерактивном меню один конкретный тест запускается так: Автоматические тесты -> Показать список тестов -> Выбрать тест из списка -> ввести номер теста.

### LDAP: базовая ручная проверка

1. Запусти python run.py.
2. Выбери 1. Ручной ввод события.
3. Выбери 1. LDAP.
4. Введи BindRequest.name.
5. Доменный контекст можно оставить пустым, если проверяешь полный идентификатор. Для спорных доменных случаев вводи pastukhov.lab или domain3.lab.
6. Смотри Краткий итог, JSON-результат и Trace проверки.

Минимальный набор LDAP-вводов:

| Что проверяем | BindRequest.name | Ожидаемый смысл |
|---|---|---|
| UPN | userA@pastukhov.lab | Найден userA, формат userPrincipalName. |
| Down-level | PASTUKHOV\userA | Найден userA, формат downLevelLogonName. |
| DN | CN=userA,CN=Users,DC=pastukhov,DC=lab | Найден userA, формат distinguishedName. |
| canonicalName | pastukhov.lab/Users/userA | Найден userA, формат canonicalName. |
| objectGUID | {5c69b042-e0e9-475a-ae37-1751ef9e05e7} | Найден userA, формат objectGUID. |
| displayName | User A | Найден userA, формат displayName. |
| SPN | HTTP/userA | Найден userA, формат servicePrincipalName. |
| MapSPN | HOST/userA | Найден userA, формат MapSPN, потому что HOST мапится на HTTP. |
| SID | S-1-5-21-2845156888-2425353457-3474467337-1114 | Найден userA, формат objectSid. |
| sIDHistory | S-1-5-21-2845156888-2425353457-3474467337-5114 | Найден userA, формат sIDHistory. |
| canonicalName с LF | Лучше смотреть автоматический тест ldap_canonical_lf_userA | Ввод с переводом строки руками неудобен. |

Что смотреть в результате:

- matched_format - какой формат реально победил.
- matched_field - по какому полю snapshot нашли объект.
- matched_object_id - какой объект найден.
- trace - какие проверки были до найденного результата.

### LDAP: корнеры и спорные случаи

#### Generated UPN

1. Ручной режим -> LDAP.
2. Введи userImplicit@pastukhov.lab.
3. Доменный контекст можно оставить пустым.
4. Ожидай matched_format = generatedUPN, matched_object_id = userImplicit.

Смысл: у объекта нет явного userPrincipalName, но строка собирается как sAMAccountName=userImplicit + domainFQDN=pastukhov.lab.

#### Явный UPN должен победить generated UPN

1. Ручной режим -> LDAP.
2. Введи userImplicitOwner@pastukhov.lab.
3. Ожидай matched_format = userPrincipalName, matched_object_id = userConflict.

Смысл: такая же строка могла бы выглядеть как generated UPN для userImplicitOwner, но у userConflict она явно записана в userPrincipalName. Поэтому явный UPN проверяется раньше и побеждает.

#### Один и тот же UPN-like в разных доменах

1. Ручной режим -> LDAP.
2. Введи userTrust@pastukhov.lab.
3. В доменном контексте введи pastukhov.lab.
4. Ожидай matched_object_id = userTrustPastukhov.
5. Повтори то же, но доменный контекст введи domain3.lab.
6. Ожидай matched_object_id = userTrustDomain3.

Смысл: snapshot продуктовый, он видит несколько доменов. Контекст помогает выбрать локальный объект, если одинаковое значение найдено в нескольких доменах.

#### displayName совпадает с другим форматом

Проверь, что более ранний формат побеждает displayName:

| Ввод | Ожидаемый объект | Почему |
|---|---|---|
| cornerUpnTarget@pastukhov.lab | cornerUpnTarget | UPN проверяется раньше displayName userDisplayUpn. |
| PASTUKHOV\cornerDownlevelTarget | cornerDownlevelTarget | Down-level проверяется раньше displayName userDisplayNetbios. |
| CN=cornerDnTarget,CN=Users,DC=pastukhov,DC=lab | cornerDnTarget | DN проверяется первым, раньше displayName userDisplayDn. |
| pastukhov.lab/Users/cornerCanonicalTarget | cornerCanonicalTarget | canonicalName раньше displayName userDisplayCanonical. |
| {cccccccc-0000-0000-0000-000000000066} | cornerGuidTarget | objectGUID раньше displayName userDisplayGuid. |
| HTTP/cornerSpnTarget | userDisplaySpn | По текущему LDAP-порядку из статьи displayName идет раньше servicePrincipalName, поэтому displayName совпадение победит SPN. |
| S-1-5-21-2845156888-2425353457-3474467337-1668 | userDisplaySid | По текущему LDAP-порядку из статьи displayName идет раньше objectSid, поэтому displayName совпадение победит SID. |

Для пары SPN/SID специально смотри trace: так быстрее понять, какой именно шаг сработал раньше и соответствует ли это порядку из статьи.

#### Несколько одинаковых displayName

1. Ручной режим -> LDAP.
2. Введи Same Display.
3. Ожидай resolved=false, reason=not_unique, matched_format=displayName.

Смысл: совпало несколько объектов, поэтому стабильный JSON не выбирает случайного пользователя.

#### DN со спецсимволами

Запускай раздел целиком:

~~~powershell
python run.py --run-category ldap_dn_special
~~~

Или вручную вводи примеры:

| Спецсимвол | BindRequest.name |
|---|---|
| Запятая | CN=user\,A,CN=Users,DC=pastukhov,DC=lab |
| Плюс | CN=user\+A,CN=Users,DC=pastukhov,DC=lab |
| Кавычки | CN=user\"A\",CN=Users,DC=pastukhov,DC=lab |
| Обратный слеш | CN=user\\A,CN=Users,DC=pastukhov,DC=lab |
| Угловые скобки | CN=user\<A\>,CN=Users,DC=pastukhov,DC=lab |
| Точка с запятой | CN=user\;A,CN=Users,DC=pastukhov,DC=lab |
| Равно | CN=user\=A,CN=Users,DC=pastukhov,DC=lab |
| Slash | CN=user/A,CN=Users,DC=pastukhov,DC=lab |
| Ведущий # | CN=\#userA,CN=Users,DC=pastukhov,DC=lab |

Важно: прототип не делает полную LDAP-нормализацию DN. Он проверяет, что DN выглядит как DN, корректно не ломается на escaped comma и затем ищет точное значение в snapshot.

### Kerberos: базовая ручная проверка

1. Запусти python run.py.
2. Выбери 1. Ручной ввод события.
3. Выбери 2. Kerberos.
4. Выбери тип сообщения:
   - AS-REQ - проверка клиентского имени, поле cname, ветка Client Principal Lookup.
   - TGS-REQ - проверка сервисного имени, поле sname, ветка Server Principal Lookup.
5. Введи name_type.
6. Введи name_string[] через запятую. Это массив компонентов principal, а не одна произвольная строка.
7. Введи realm. Если CLI предложил default, можно нажать Enter.
8. Смотри matched_format, input_field, input_value, matched_object_id и trace.

#### AS-REQ / cname / Client Principal Lookup

| Что проверяем | message_type | name_type | name_string[] | realm | Ожидаемый смысл |
|---|---|---:|---|---|---|
| UPN как NT-ENTERPRISE | AS-REQ | 10 | userA@pastukhov.lab | PASTUKHOV.LAB | Найден userA, формат NT-ENTERPRISE/userPrincipalName. |
| Generated UPN | AS-REQ | 10 | userImplicit@pastukhov.lab | PASTUKHOV.LAB | Найден userImplicit, формат NT-ENTERPRISE/generatedUPN. |
| Account name | AS-REQ | 1 | userA | PASTUKHOV.LAB | Найден userA, формат NT-PRINCIPAL/sAMAccountName. |
| Machine account через $ fallback | AS-REQ | 1 | 10-23-RP-DC-01 | PASTUKHOV.LAB | Найден dc01, формат NT-PRINCIPAL/sAMAccountName+$. |
| UPN fallback из account + realm | AS-REQ | 1 | userUpnSetX | PASTUKHOV.LAB | Найден userUpnSet, формат NT-PRINCIPAL/userPrincipalName. |
| DN не является Kerberos client principal | AS-REQ | 10 | CN=userA,CN=Users,DC=pastukhov,DC=lab | PASTUKHOV.LAB | Не должен находить пользователя как DN. |

#### TGS-REQ / sname / Server Principal Lookup

| Что проверяем | message_type | name_type | name_string[] | realm | Ожидаемый смысл |
|---|---|---:|---|---|---|
| Обычный service/host как SRV-INST | TGS-REQ | 2 | cifs,10-23-RP-DC-01.pastukhov.lab | PASTUKHOV.LAB | В текущей ветке проверяется service-string как UPN; по статье это отдельная проверка server principal. |
| krbtgt special case | TGS-REQ | 2 | krbtgt,krbtgt | PASTUKHOV.LAB | Найден krbtgt. |
| Single component + $ fallback | TGS-REQ | 2 | 10-23-RP-DC-01 | PASTUKHOV.LAB | Найден dc01, формат NT-SRV-INST/sAMAccountName+$. |
| Enterprise SPN для DC | TGS-REQ | 10 | cifs/10-23-RP-DC-01.pastukhov.lab | PASTUKHOV.LAB | Найден dc01, формат NT-ENTERPRISE/servicePrincipalName. |
| Enterprise SPN для пользователя | TGS-REQ | 10 | HTTP/userA | PASTUKHOV.LAB | Найден userA, формат NT-ENTERPRISE/servicePrincipalName. |
| Enterprise account с зарегистрированным SPN | TGS-REQ | 10 | userA | PASTUKHOV.LAB | Найден userA, потому что у него есть SPN. |
| Enterprise account без SPN | TGS-REQ | 10 | userUpnSet | PASTUKHOV.LAB | Не найден как server principal, потому что у объекта нет зарегистрированного SPN. |

## Если проверять на реальном трафике

### LDAP в Wireshark

1. Включи capture на клиенте или на участке до DC.
2. Фильтр: ldap или tcp.port == 389.
3. Сделай LDAP Simple Bind тестовым клиентом.
4. В пакете открой LDAPMessage -> protocolOp: bindRequest -> bindRequest -> name.
5. Именно это поле сравнивай с тем, что вводишь в прототип как BindRequest.name.
6. Пароль/credential не нужен для проверки формата имени: он относится к проверке секрета, а не к определению формата.

### Kerberos в Wireshark

1. Очисти билеты на клиенте:

~~~powershell
klist purge
~~~

2. Для проверки клиентского имени сделай логон/получение TGT, например:

~~~powershell
runas /user:userA@pastukhov.lab cmd
runas /user:PASTUKHOV\userA cmd
~~~

3. В Wireshark смотри AS-REQ: cname.name-type, cname.name-string[], realm.
4. Для проверки сервисного имени вызови доступ к ресурсу, например:

~~~powershell
dir \\10-23-RP-DC-01.pastukhov.lab\SYSVOL
~~~

5. В Wireshark смотри TGS-REQ: sname.name-type, sname.name-string[], realm.
6. В прототип руками вводи уже эти разобранные поля, а не исходную строку, которую набирал пользователь.

## Kerberos-шпаргалка: что во что превращается

Это обратная сторона относительно lookup-алгоритма из статьи.

- В статье и схемах основная логика описывает сторону KDC/AD lookup: уже есть principal из трафика, дальше KDC/продукт ищет AD-объект.
- Перепроверка по исходникам Windows больше похожа на клиентскую сторону: пользователь или API передал строку, Windows/SSPI превращает ее в Kerberos principal, и уже потом этот principal попадает в AS-REQ/TGS-REQ.

| Что ввел пользователь / что запросило приложение | Что обычно появляется в Kerberos | Что дальше делает lookup |
|---|---|---|
| userA@pastukhov.lab как пользовательский логон | AS-REQ, cname.name-type = 10, cname.name-string = [userA@pastukhov.lab], realm = PASTUKHOV.LAB | Client Principal Lookup: сначала явный UPN, потом generated UPN, потом fallback по realm. |
| PASTUKHOV\userA | AS-REQ, cname.name-type = 1, cname.name-string = [userA], realm = PASTUKHOV.LAB | Client Principal Lookup: sAMAccountName в realm, потом $ fallback, потом UPN-вариант. |
| userA без домена | Часто AS-REQ с cname.name-type = 1, cname.name-string = [userA], realm берется из текущего логон-контекста/домена | Работает только если понятен текущий realm. Для прототипа лучше вводить realm явно. |
| Доступ к \\10-23-RP-DC-01.pastukhov.lab\SYSVOL | TGS-REQ, обычно sname.name-type = 2, sname.name-string = [cifs, 10-23-RP-DC-01.pastukhov.lab], realm = PASTUKHOV.LAB | Server Principal Lookup: поиск сервисного/компьютерного объекта. |
| Запрос HTTP к http://host при Kerberos auth | TGS-REQ, service principal вида HTTP/host, часто sname.name-string = [HTTP, host] | Server Principal Lookup по сервисному principal/SPN. |
| LDAP DN CN=userA,CN=Users,DC=pastukhov,DC=lab | Для Kerberos client principal это не обычный формат пользовательского логина | В прототипе Kerberos DN считается неподдержанным/не тем форматом; DN проверяется в LDAP. |

Практический вывод: выбирать AS-REQ или TGS-REQ в прототипе нужно не потому, что это само по себе формат имени, а потому что от типа сообщения зависит, какое поле из трафика разбираем: cname для пользователя или sname для сервиса.
