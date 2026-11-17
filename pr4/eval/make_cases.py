"""Создаёт размеченные сценарии eval/labeled_cases.json (label = есть ли реальный инцидент по мнению эксперта)."""
import json, os

def F(source, port=None, service=None, version=None, description="", severity="low", cwe=None):
    return {"source": source, "type": "service", "port": port, "service": service, "version": version,
            "description": description, "severity": severity, "cwe": cwe, "cve": None}

M = lambda port: F("masscan", port=port, description=f"Открытый порт {port}")
NK = lambda msg, sev="low", cwe=None: F("nikto", port=80, description=msg, severity=sev, cwe=cwe)
NM = lambda port, svc, ver: F("nmap", port=port, service=svc, version=ver, description=f"{svc} {ver} на порту {port}")

cases = [
 # --- реальные сканы из ПР1 ---
 {"id": "R1", "title": "ВМ 192.168.0.146 (Kubernetes): открыты 22, 80, 111, 443", "label": True, "scan_dir": "data/vm"},
 {"id": "R2", "title": "Тестовый nginx с /.git/HEAD", "label": True, "scan_dir": "data/stand"},
 # --- настоящие инциденты ---
 {"id": "P1", "title": "Открыт Telnet", "label": True, "findings": [M(23), NM(23, "telnet", "Linux telnetd")]},
 {"id": "P2", "title": "SQL-инъекция найдена Nikto", "label": True, "findings": [NK("/login.php: возможна SQL injection", "critical", "CWE-89")]},
 {"id": "P3", "title": "Apache 2.2.15 (устарел)", "label": True, "findings": [NM(80, "http", "Apache httpd 2.2.15")]},
 {"id": "P4", "title": "kubelet 10250 открыт", "label": True, "findings": [M(10250), M(22)]},
 {"id": "P5", "title": "SMB 445 открыт", "label": True, "findings": [M(445)]},
 {"id": "P6", "title": "RDP 3389 открыт", "label": True, "findings": [M(3389)]},
 {"id": "P7", "title": "MySQL 3306 доступен из сети", "label": True, "findings": [NM(3306, "mysql", "MySQL 5.7.30")]},
 {"id": "P8", "title": "OpenSSH 7.4 (старая версия)", "label": True, "findings": [NM(22, "ssh", "OpenSSH 7.4")]},
 {"id": "P9", "title": "FTP с анонимным входом", "label": True, "findings": [NM(21, "ftp", "vsftpd 3.0.3"), NK("FTP: anonymous login allowed", "high")]},
 {"id": "P10", "title": "Доступен файл /.env", "label": True, "findings": [NK("/.env: файл конфигурации с секретами доступен", "high")]},
 {"id": "P11", "title": ".git найден на другом сервере", "label": True, "findings": [NK("/.git/HEAD: Git HEAD file found.", "high", "CWE-538")]},
 # --- нормальные (инцидента нет) ---
 {"id": "N1", "title": "Только SSH 9.2", "label": False, "findings": [NM(22, "ssh", "OpenSSH 9.2p1"), M(22)]},
 {"id": "N2", "title": "nginx без части заголовков", "label": False, "findings": [NM(80, "http", "nginx 1.24.0"), NK("Suggested security header missing: referrer-policy.")]},
 {"id": "N3", "title": "Чистые 80 и 443", "label": False, "findings": [M(80), M(443)]},
 {"id": "N4", "title": "Только rpcbind", "label": False, "findings": [NM(111, "rpcbind", "2-4")]},
 {"id": "N5", "title": "Порт 8080 с нормальным приложением", "label": False, "findings": [M(8080)]},
 {"id": "N6", "title": "Нет X-Frame-Options на статическом сайте", "label": False, "findings": [NK("The anti-clickjacking X-Frame-Options header is not present.", "medium", "CWE-1021")]},
 {"id": "N7", "title": "Apache 2.4.57 (актуальный)", "label": False, "findings": [NM(80, "http", "Apache httpd 2.4.57")]},
 {"id": "N8", "title": "Пустой результат (хост без открытых портов)", "label": False, "findings": []},
 # --- трудные случаи для правил ---
 {"id": "T1", "title": "Каталог /.github/ (публичные workflow) — не утечка", "label": False, "findings": [NK("/.github/workflows/: каталог найден")]},
 {"id": "T2", "title": "Apache 2.4.57 с упоминанием совместимости 2.2", "label": False, "findings": [NM(80, "http", "Apache httpd 2.4.57 (compat 2.2)")]},
]
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "labeled_cases.json"), "w", encoding="utf-8") as f:
    json.dump(cases, f, ensure_ascii=False, indent=1)
print(len(cases), "сценариев;", sum(c["label"] for c in cases), "с инцидентом")
