"""
Экспертная система принятия решений об инцидентах ИБ.
Правила лежат во внешних YAML-файлах (rules.yaml и папка rules/), а не в коде.
Решение: движок правил (какие правила сработали) + небольшое дерево решений (приоритет).
"""
import glob
import os
from dataclasses import dataclass
from typing import List, Dict

import yaml


@dataclass
class Incident:
    detected: bool
    risk_score: float
    category: str
    recommendations: List[str]
    triggering_findings: List[Dict]
    priority: str = "P4"


class ExpertSystem:
    """Движок экспертной системы на основе правил."""

    def __init__(self, rules_path: str, rules_dir: str = None):
        with open(rules_path, 'r', encoding='utf-8') as f:
            cfg = yaml.safe_load(f)
        self.threshold = cfg['threshold']
        self.rules = list(cfg['rules'])
        # дополнительные правила, созданные менеджером правил (Java)
        rules_dir = rules_dir or os.path.join(os.path.dirname(os.path.abspath(rules_path)), 'rules')
        for path in sorted(glob.glob(os.path.join(rules_dir, '*.yaml'))):
            with open(path, 'r', encoding='utf-8') as f:
                extra = yaml.safe_load(f)
            if isinstance(extra, list):
                self.rules.extend(extra)

    def evaluate(self, findings: List[Dict]) -> Incident:
        """Оценка findings и вывод об инциденте."""
        triggered = []
        risk_score = 0.0
        categories = []
        recommendations = []

        for rule in self.rules:
            matching = self._get_matching_findings(rule, findings)
            if matching:
                triggered.append({'rule': rule['name'], 'risk_score': rule['risk_score'], 'findings': matching})
                risk_score = max(risk_score, rule['risk_score'])
                if rule['category'] not in categories:
                    categories.append(rule['category'])
                for r in rule.get('recommendations', []):
                    if r not in recommendations:
                        recommendations.append(r)

        detected = risk_score >= self.threshold
        return Incident(
            detected=detected,
            risk_score=risk_score,
            category=', '.join(categories) if categories else 'none',
            recommendations=recommendations,
            triggering_findings=triggered,
            priority=self.decide_priority(detected, risk_score, len(triggered)),
        )

    @staticmethod
    def decide_priority(detected: bool, risk_score: float, rules_hit: int) -> str:
        """Дерево решений: приоритет реагирования."""
        if not detected:
            return "P4" if rules_hit == 0 else "P3"     # P3 — есть замечания, но ниже порога
        if risk_score >= 9.0:
            return "P1"                                  # реагировать немедленно
        if rules_hit >= 2:
            return "P2"                                  # несколько проблем сразу
        return "P2" if risk_score >= 8.0 else "P3"

    def _check_condition(self, finding: Dict, condition: Dict) -> bool:
        field, operator, value = condition['field'], condition['operator'], condition['value']
        actual = finding.get(field)
        if actual is None:
            return False
        if operator == 'eq':
            return actual == value
        if operator == 'in':
            return actual in value
        if operator == 'gte':
            return actual >= value
        if operator == 'contains':
            return str(value).lower() in str(actual).lower()
        return False

    def _get_matching_findings(self, rule: Dict, findings: List[Dict]) -> List[Dict]:
        """Находки, для которых выполнены все условия правила."""
        return [f for f in findings if all(self._check_condition(f, c) for c in rule['conditions'])]
