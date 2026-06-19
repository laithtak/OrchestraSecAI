from orchestrasecai.checks import BUILTIN_CHECKS
from orchestrasecai.checks.base import SecurityCheck


class CheckRegistry:
    def __init__(self) -> None:
        self._checks: dict[str, SecurityCheck] = {}

    def register(self, check_cls: type[SecurityCheck]) -> None:
        instance = check_cls()
        keys = {instance.plugin_id, *getattr(instance, "aliases", [])}
        for key in keys:
            self._checks[key] = instance

    def get(self, plugin_id: str) -> SecurityCheck | None:
        return self._checks.get(plugin_id)

    def get_many(self, plugin_ids: list[str]) -> list[SecurityCheck]:
        seen = set()
        result = []
        for pid in plugin_ids:
            check = self.get(pid)
            if check and check.plugin_id not in seen:
                seen.add(check.plugin_id)
                result.append(check)
        return result

    def all_checks(self) -> list[SecurityCheck]:
        return list({id(c): c for c in self._checks.values()}.values())


def build_registry() -> CheckRegistry:
    registry = CheckRegistry()
    for cls in BUILTIN_CHECKS:
        registry.register(cls)
    return registry
