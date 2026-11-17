# Экспертная оценка (ПР2)

Проверены три проекта: Python (VulnMart), C++ (vulnerable.cpp), JavaScript (vulnerable.js). Найдено 12 уязвимостей, 9 классов (CWE-89, 79, 639, 256, 798, 307, 120, 134, 78).

| Язык | Тип | CWE | OWASP | CVSS (эксперт) | Критичность |
|------|-----|-----|-------|----------------|-------------|
| Python | SQL Injection | CWE-89 | A03 | 9.8 | Critical |
| Python | Stored XSS | CWE-79 | A03 | 6.1 | Medium |
| Python | IDOR | CWE-639 | A01 | 6.5 | Medium |
| Python | Пароли в открытом виде | CWE-256 | A02 | 7.5 | High |
| Python | Жёсткий secret_key | CWE-798 | A07 | 9.1 | High |
| Python | Нет лимита попыток входа | CWE-307 | A07 | 7.5 | High |
| C++ | Buffer Overflow | CWE-120 | — | 7.8 | High |
| C++ | Format String | CWE-134 | A03 | 7.8 | High |
| C++ | Command Injection | CWE-78 | A03 | 7.8 | High |
| JavaScript | SQL Injection | CWE-89 | A03 | 9.8 | Critical |
| JavaScript | Reflected XSS | CWE-79 | A03 | 6.1 | Medium |
| JavaScript | Command Injection | CWE-78 | A03 | 9.8 | Critical |

## Что показали инструменты

- SAST нашёл мало. Bandit по VulnMart: 0 замечаний. Cppcheck: только советы по стилю, ни strcpy, ни printf, ни system не отметил. ESLint (security): одно замечание, на exec().
- Дополнительно Ruff нашёл SQL-инъекцию (S608) и жёсткий ключ (S105), Flawfinder отметил все 3 опасные функции в C++.
- DAST (ручные запросы) подтвердил все уязвимости на деле. Логические ошибки (IDOR, отсутствие лимита попыток, XSS через |safe) статический анализ не видит совсем.
- Вывод: нужен набор инструментов, а не один сканер, и обязательно динамическая проверка.

## Рекомендации

1. **Python:** параметризованные запросы (`WHERE username = ?`), убрать `|safe`, добавить `AND user_id = ?` в запрос заказа, хешировать пароли (`generate_password_hash`), ключ сессии брать из переменной окружения, ограничить число попыток входа (Flask-Limiter).
2. **C++:** `std::string` или `snprintf`/`strncpy` с ограничением длины, `printf("%s", input)`, вместо `system()` — `execve`/`fork` без оболочки.
3. **JavaScript:** параметризованные запросы (`db.get('... ?', [username])`), экранирование вывода или шаблонизатор, `execFile('ping', ['-c','1',host])` с проверкой host по шаблону.

## Источники CVE (проверены по NVD)

CVE-2019-25676, CVE-2020-37243, CVE-2005-3308, CVE-2019-7890, CVE-2026-86715, CVE-2017-16338, CVE-2012-0809, CVE-2026-30880. В задании встречались также CVE-2026-89633 и CVE-2026-89749: первая в NVD есть, но с оценкой 9.8, а не 10.0 или 9.5, как в задании; для найденных уязвимостей ни одна из них не подходит, поэтому в датасет не вошли.
