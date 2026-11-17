#!/bin/bash
# Оценка качества детекции: до и после добавления правил через менеджер правил (Java)
cd "$(dirname "$0")/.."
python3 eval/make_cases.py
echo; echo "=== 1. Базовые правила (rules.yaml) ==="
python3 evaluate.py --base
echo; echo "=== 2. Добавляем недостающие правила через RuleManager (Java) ==="
java RuleManager add "Открыт MySQL" data_breach 8.0 service eq mysql "Закрыть порт 3306 для внешней сети" | tail -1
java RuleManager add "Открыт FTP" unauthorized_access 8.0 service eq ftp "Заменить FTP на SFTP" | tail -1
java RuleManager add "Устаревший OpenSSH" vulnerable_component 7.5 version contains "OpenSSH 7." "Обновить OpenSSH" | tail -1
java RuleManager add "Доступен .env" information_disclosure 8.5 description contains ".env" "Убрать .env из корня сайта" | tail -1
echo; echo "=== 3. После добавления правил ==="
python3 evaluate.py
