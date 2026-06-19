from pathlib import Path

import yaml
from jinja2 import Template

_PROMPTS_DIR = Path(__file__).parent


def load_prompt(name: str, version: str = "v1") -> dict:
    path = _PROMPTS_DIR / name / f"{version}.yaml"
    with open(path) as f:
        return yaml.safe_load(f)


def render_prompt(name: str, version: str, **kwargs) -> tuple[str, str, str]:
    data = load_prompt(name, version)
    system = data.get("system", "")
    user_tpl = Template(data.get("user", ""))
    user = user_tpl.render(**kwargs)
    return system, user, data.get("version", version)
