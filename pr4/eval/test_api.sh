#!/bin/bash
# Проверка REST API: запуск сервиса, запрос сканирования, чтение списка инцидентов
cd "$(dirname "$0")/.."
[ -f api ] || go build -o api api.go
nohup ./api > /tmp/ias_api.log 2>&1 &
sleep 2
echo '$ curl -s http://127.0.0.1:8080/health'
curl -s http://127.0.0.1:8080/health; echo
echo; echo '$ curl -s -X POST http://127.0.0.1:8080/scan -d "{\"target\":\"127.0.0.1; id\"}"   # проверка защиты от инъекции'
curl -s -w ' [HTTP %{http_code}]\n' -X POST http://127.0.0.1:8080/scan -d '{"target":"127.0.0.1; id"}'
echo; echo '$ curl -s -X POST http://127.0.0.1:8080/scan -d "{\"target\":\"127.0.0.1\"}"'
curl -s -X POST http://127.0.0.1:8080/scan -d '{"target":"127.0.0.1"}' > eval/api_scan_127.0.0.1.json
python3 - <<'PY'
import json
d = json.load(open('eval/api_scan_127.0.0.1.json', encoding='utf-8'))
i = d['incident']
print('target:', d['target'], '| находок:', len(d['findings']))
print('detected:', i['detected'], '| priority:', i['priority'], '| risk_score:', i['risk_score'])
print('category:', i['category']); print('rules:', i['triggered_rules'])
for f in d['findings']:
    print('  ', f['source'], f['severity'], f.get('port'), f['description'][:70])
PY
echo; echo '$ curl -s http://127.0.0.1:8080/incidents | python3 -c "..."'
curl -s http://127.0.0.1:8080/incidents | python3 -c "import sys,json; print('хранится целей:', list(json.load(sys.stdin).keys()))"
pkill -f "./api"; exit 0
