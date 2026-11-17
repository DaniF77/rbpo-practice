#!/bin/bash
# Проверка эндпоинта /reliability в VulnMart (запуск из папки pr3)
cd "$(dirname "$0")/vulnmart"
rm -f vulnmart.db
nohup python3 app.py > /tmp/vm3.log 2>&1 &
sleep 3
echo '$ curl "http://localhost:5055/reliability?t=100&i=30&Ec=30"'
curl -s "http://localhost:5055/reliability?t=100&i=30&Ec=30" | python3 -m json.tool
echo; echo '$ curl "http://localhost:5055/reliability?t=200&i=40&Ec=45"   # больше исправлено ошибок, дольше время'
curl -s "http://localhost:5055/reliability?t=200&i=40&Ec=45" | python3 -c "import sys,json; d=json.load(sys.stdin); print('JM R =',d['jelinski_moranda']['R'],' MTTF =',d['jelinski_moranda']['MTTF'],'| Schuman R =',d['schuman']['R'])"
echo; echo '$ curl "http://localhost:5055/reliability?i=60"   # ошибок исправлено больше, чем было (N0=50)'
curl -s -w ' [HTTP %{http_code}]\n' "http://localhost:5055/reliability?i=60"
echo; echo '$ curl -s -o /dev/null -w "%{http_code}" http://localhost:5055/   # остальное приложение работает'
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:5055/
pkill -f "python3 app.py"; exit 0
