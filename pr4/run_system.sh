#!/bin/bash
# =============================================================================
# Запуск ИАС БИ — полный цикл: сканеры -> парсеры -> экспертная система
# Использование: ./run_system.sh <цель>   (запускать под root: нужен Masscan)
# =============================================================================
set -e
cd "$(dirname "$0")"
TARGET=${1:-127.0.0.1}
OUT="./scan_results"
mkdir -p "$OUT"

echo "=== ИАС БИ: сканирование $TARGET ==="
echo "[1/6] Nmap...";    nmap -sV -oX "$OUT/nmap.xml" "$TARGET" > /dev/null
echo "[2/6] Masscan..."; masscan -p1-1000,6443,10250 "$TARGET" --rate 100 --wait 3 -oJ "$OUT/masscan.json" > /dev/null 2>&1 || true
echo "[3/6] Nikto...";   nikto -h "$TARGET" -maxtime 60s -nointeractive -Format json -o "$OUT/nikto.json" > /dev/null 2>&1 || true

echo "[4/6] Парсинг Nmap XML (C++)..."
./nmap_parser "$OUT/nmap.xml" > "$OUT/nmap_parsed.json"

echo "[5/6] Парсинг JSON и приведение к единой схеме (Python)..."
echo "[6/6] Экспертная система..."
python3 analyze.py "$OUT" "$TARGET" > "$OUT/incident.json"

python3 - "$OUT/incident.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding='utf-8'))
i = d['incident']
print(f"Всего находок: {len(d['findings'])}")
print(f"Инцидент обнаружен: {i['detected']}   приоритет: {i['priority']}   риск: {i['risk_score']}")
print("Категория:", i['category'])
print("Сработавшие правила:", '; '.join(i['triggered_rules']) or '—')
for r in i['recommendations']:
    print("  -", r)
PY
echo "=== Готово! Результаты в $OUT ==="
