"""
Единый конвейер анализа: читает выводы сканеров из папки, приводит находки к единой схеме,
применяет экспертную систему и печатает результат в JSON (схема из п. 2.2 задания).
Запуск: python3 analyze.py <папка_со_сканами> <цель>
"""
import json
import os
import sys
import uuid
from datetime import datetime, timezone

from parsers import MasscanParser, NiktoParser, NmapJSONParser
from expert_system import ExpertSystem

HERE = os.path.dirname(os.path.abspath(__file__))


def collect(scan_dir: str):
    findings = []
    for name, parser in (('masscan.json', MasscanParser), ('nikto.json', NiktoParser), ('nmap_parsed.json', NmapJSONParser)):
        path = os.path.join(scan_dir, name)
        if os.path.exists(path) and os.path.getsize(path) > 0:
            try:
                findings += parser.parse(path)
            except Exception as e:                       # один сломанный файл не должен ронять всё
                print(f"[!] {name}: {e}", file=sys.stderr)
    return findings


def build_result(target: str, findings, es: ExpertSystem):
    inc = es.evaluate(findings)
    return {
        'scan_id': str(uuid.uuid4()),
        'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'target': target,
        'findings': findings,
        'incident': {
            'detected': inc.detected, 'risk_score': inc.risk_score, 'priority': inc.priority,
            'category': inc.category, 'recommendations': inc.recommendations,
            'triggered_rules': [t['rule'] for t in inc.triggering_findings],
        },
    }


if __name__ == '__main__':
    scan_dir, target = sys.argv[1], sys.argv[2]
    es = ExpertSystem(os.path.join(HERE, 'rules.yaml'))
    print(json.dumps(build_result(target, collect(scan_dir), es), ensure_ascii=False, indent=2))
