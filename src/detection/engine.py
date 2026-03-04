"""Rule evaluation engine.

Loads detection rules from the rules module and evaluates each incoming
event against every active rule. Rules are simple predicate functions that
return a DetectionResult — keeping the engine easy to extend without touching
the core loop.
"""

from typing import List

from src.shared.logger import get_logger
from src.shared.models import SecurityEvent, DetectionResult
from src.detection import rules as rule_definitions

logger = get_logger(__name__)


class DetectionEngine:
    """Stateless engine that evaluates events against registered rules."""

    def __init__(self):
        self._rules = rule_definitions.get_all_rules()
        logger.info(f"Detection engine initialised with {len(self._rules)} rules")

    def evaluate(self, event: SecurityEvent) -> List[DetectionResult]:
        results = []
        for rule_fn in self._rules:
            try:
                result = rule_fn(event)
                if result:
                    results.append(result)
            except Exception:
                logger.exception(f"Rule {rule_fn.__name__} raised an exception")
        return results

    def reload_rules(self):
        """Hot-reload rules without redeploying the Lambda."""
        self._rules = rule_definitions.get_all_rules()
        logger.info(f"Rules reloaded: {len(self._rules)} active")
