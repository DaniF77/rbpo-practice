"""
Парсеры вывода сканеров (Masscan, Nikto, разобранный Nmap) — приведение к единой схеме findings.
"""
import json
from typing import List, Dict


def _load_json_any(filepath: str):
    """Читает JSON целиком; если не получилось (Masscan пишет по объекту в строке) — читает построчно."""
    with open(filepath, 'r', encoding='utf-8') as f:
        text = f.read()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        items = []
        for line in text.splitlines():
            line = line.strip().rstrip(',')
            if line in ('', '[', ']'):
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return items


class MasscanParser:
    """Парсер вывода Masscan (JSON)."""
    SEVERITY_MAP = {
        22: "medium",      # SSH
        23: "high",        # Telnet
        111: "medium",     # rpcbind
        445: "critical",   # SMB
        3306: "high",      # MySQL
        3389: "high",      # RDP
        5432: "high",      # PostgreSQL
        6443: "high",      # Kubernetes API
        8080: "medium",    # HTTP-alt
        10250: "high",     # kubelet
    }

    @staticmethod
    def parse(filepath: str) -> List[Dict]:
        findings = []
        for data in _load_json_any(filepath):
            for port_info in data.get('ports', []):
                port = port_info.get('port')
                findings.append({
                    'source': 'masscan', 'type': 'port', 'port': port,
                    'protocol': port_info.get('proto', 'tcp'),
                    'state': port_info.get('status', 'open'),
                    'severity': MasscanParser.SEVERITY_MAP.get(port, 'low'),
                    'description': f"Открытый порт {port}",
                    'cwe': None, 'cve': None,
                })
        return findings


class NiktoParser:
    """Парсер вывода Nikto (JSON, версия 2.6: массив хостов с полем vulnerabilities)."""

    @staticmethod
    def parse(filepath: str) -> List[Dict]:
        findings = []
        data = _load_json_any(filepath)
        hosts = data if isinstance(data, list) else [data]
        for host in hosts:
            for v in host.get('vulnerabilities', []):
                msg = v.get('msg', '')
                url = v.get('url')
                if url and url != '/':
                    msg = f"{url}: {msg}"          # путь к файлу важен для оценки (например, /.git/HEAD)
                findings.append({
                    'source': 'nikto', 'type': 'vulnerability',
                    'port': host.get('port', 80), 'protocol': 'http', 'state': 'found',
                    'severity': NiktoParser._severity(msg),
                    'description': msg,
                    'url': url,
                    'cwe': NiktoParser._map_cwe(msg), 'cve': None,
                })
        return findings

    @staticmethod
    def _severity(msg: str) -> str:
        m = msg.lower()
        if 'sql' in m or 'injection' in m:
            return 'critical'
        if '.git' in m or 'backup' in m or '.env' in m:
            return 'high'
        if 'x-frame-options' in m or 'x-content-type' in m or 'outdated' in m or 'certificate' in m:
            return 'medium'
        return 'low'

    @staticmethod
    def _map_cwe(msg: str):
        m = msg.lower()
        if 'sql' in m:
            return 'CWE-89'
        if 'xss' in m or 'script' in m:
            return 'CWE-79'
        if 'x-frame-options' in m:
            return 'CWE-1021'
        if '.git' in m:
            return 'CWE-538'
        if 'outdated' in m:
            return 'CWE-1104'
        if 'does not match certificate' in m or 'hostname' in m and 'cert' in m:
            return 'CWE-297'
        if 'header' in m and 'missing' in m or 'not present' in m:
            return 'CWE-693'
        return None


class NmapJSONParser:
    """Парсер JSON-вывода C++ парсера Nmap."""

    @staticmethod
    def parse(filepath: str) -> List[Dict]:
        findings = []
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        for host in data.get('hosts', []):
            for port in host.get('ports', []):
                if port.get('state') == 'open':
                    findings.append({
                        'source': 'nmap', 'type': 'service',
                        'port': port.get('port'), 'protocol': port.get('protocol', 'tcp'),
                        'state': port.get('state'), 'service': port.get('service'),
                        'version': port.get('version'),
                        'severity': NmapJSONParser._severity(port),
                        'description': f"{port.get('service')} {port.get('version')} на порту {port.get('port')}",
                        'cwe': None, 'cve': None,
                    })
        return findings

    @staticmethod
    def _severity(port: Dict) -> str:
        text = f"{port.get('service') or ''} {port.get('version') or ''}".lower()
        if 'apache' in text and ('2.2' in text or '2.4.1' in text):
            return 'high'
        if 'openssh' in text and any(x in text for x in ('openssh 7.', 'openssh 6.', 'openssh 5.')):
            return 'high'
        if 'nginx' in text and 'nginx 1.1' in text:
            return 'medium'
        if (port.get('service') or '').lower() in ('telnet', 'ftp', 'rlogin'):
            return 'critical'
        return 'low'
