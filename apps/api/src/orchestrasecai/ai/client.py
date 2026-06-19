import json
from pathlib import Path
from typing import Any

import httpx
import yaml

from orchestrasecai.config import get_settings

settings = get_settings()
PROMPTS_DIR = Path(__file__).parent / "prompts"


def load_prompt(name: str, version: str = "v1") -> dict:
    path = PROMPTS_DIR / name / f"{version}.yaml"
    with open(path) as f:
        return yaml.safe_load(f)


class LLMClient:
    def __init__(self) -> None:
        self.base_url = settings.vllm_base_url.rstrip("/")
        self.model = settings.vllm_model
        self.mock = settings.mock_ai

    async def complete(self, system: str, user: str) -> dict[str, Any]:
        if self.mock:
            return self._mock_response(user)
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                f"{self.base_url}/chat/completions",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "temperature": 0.2,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                return {"raw": content}

    def _mock_response(self, user: str) -> dict[str, Any]:
        if "prioritize" in user.lower() or "rank" in user.lower():
            return {"ranked_ids": [], "summary": "Mock prioritization complete."}
        if "executive" in user.lower():
            return {
                "executive_summary": "Mock executive summary: passive scan completed with findings requiring review.",
                "key_risks": ["Missing security headers", "Cookie configuration issues"],
            }
        if "technical" in user.lower():
            return {
                "technical_report": "Mock technical report with remediation steps based on evidence only.",
                "remediation_plan": ["Review security headers", "Harden cookie flags", "Renew TLS certificates"],
            }
        return {
            "explanations": [
                {
                    "risk_summary": "Mock AI explanation based on passive evidence.",
                    "remediation": ["Apply recommended security header", "Review configuration"],
                }
            ]
        }
