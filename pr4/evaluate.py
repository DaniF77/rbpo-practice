"""
Оценка качества детекции инцидентов: Precision, Recall, F1, Accuracy.
Запуск: python3 evaluate.py            — прогон размеченных сценариев через экспертную систему
        python3 evaluate.py --base     — только базовые правила (rules.yaml), без папки rules/
"""
import json
import os
import sys
import tempfile
from typing import Dict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from expert_system import ExpertSystem   # noqa: E402
from analyze import collect               # noqa: E402


class DetectorEvaluator:
    """Оценка качества детектора инцидентов."""

    def __init__(self):
        self.tp = self.fp = self.fn = self.tn = 0

    def add_result(self, predicted: bool, actual: bool):
        if predicted and actual:
            self.tp += 1
        elif predicted and not actual:
            self.fp += 1
        elif not predicted and actual:
            self.fn += 1
        else:
            self.tn += 1

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        total = self.tp + self.fp + self.fn + self.tn
        return (self.tp + self.tn) / total if total else 0.0

    def report(self) -> Dict:
        return {
            'precision': round(self.precision, 4), 'recall': round(self.recall, 4),
            'f1_score': round(self.f1, 4), 'accuracy': round(self.accuracy, 4),
            'confusion_matrix': {'TP': self.tp, 'FP': self.fp, 'FN': self.fn, 'TN': self.tn},
        }


def load_cases():
    with open(os.path.join(HERE, 'eval', 'labeled_cases.json'), encoding='utf-8') as f:
        cases = json.load(f)
    for c in cases:                      # реальные сканы подгружаем из папки data/
        if 'scan_dir' in c:
            c['findings'] = collect(os.path.join(HERE, c['scan_dir']))
    return cases


if __name__ == "__main__":
    base_only = '--base' in sys.argv
    rules_dir = tempfile.mkdtemp() if base_only else None     # пустая папка = только rules.yaml
    es = ExpertSystem(os.path.join(HERE, 'rules.yaml'), rules_dir)
    ev = DetectorEvaluator()
    mistakes = []
    for c in load_cases():
        pred = es.evaluate(c['findings']).detected
        ev.add_result(pred, c['label'])
        if pred != c['label']:
            mistakes.append(f"{'FP' if pred else 'FN'}: {c['id']} — {c['title']}")
    print(f"Правил в системе: {len(es.rules)}   сценариев: {ev.tp + ev.fp + ev.fn + ev.tn}")
    print(json.dumps(ev.report(), indent=2, ensure_ascii=False))
    print("Ошибки детектора:" if mistakes else "Ошибок нет")
    for m in mistakes:
        print("  ", m)
