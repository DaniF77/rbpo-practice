# ПР4. Информационно-аналитическая система безопасности (ИАС БИ)

Цепочка: сканеры (Nmap, Masscan, Nikto) → парсеры (C++ для XML, Python для JSON) → единая схема → экспертная система (правила в YAML + дерево решений) → REST API на Go → веб-дашборд.

| Файл | Назначение |
|------|-----------|
| `nmap_parser.cpp` | быстрый разбор XML Nmap в JSON (C++, libxml2) |
| `parsers.py` | разбор Masscan, Nikto и результата C++ парсера, приведение к единой схеме |
| `expert_system.py`, `rules.yaml`, `rules/` | движок правил, приоритет по дереву решений, правила во внешних файлах |
| `analyze.py` | конвейер: чтение результатов, оценка, итоговый JSON |
| `RuleManager.java` | управление правилами (список, добавление, поиск по категории) |
| `api.go` | REST API: `POST /scan`, `GET /incidents`, `GET /health` (сканеры запускаются параллельно) |
| `dashboard.html` | веб-дашборд |
| `run_system.sh` | полный запуск: `./run_system.sh <IP>` |
| `evaluate.py`, `eval/` | размеченные сценарии и оценка Precision/Recall/F1 |
| `data/` | реальные результаты сканов из ПР1 (ВМ и тестовый nginx) |

Запуск под Linux (WSL): `g++ -O2 -std=c++17 -I/usr/include/libxml2 -o nmap_parser nmap_parser.cpp -lxml2`, `javac RuleManager.java`, `go build -o api api.go`, затем `./run_system.sh 127.0.0.1`.
