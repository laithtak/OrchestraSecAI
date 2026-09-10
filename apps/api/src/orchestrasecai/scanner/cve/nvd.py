"""NVD CVE lookup with Redis caching."""

from __future__ import annotations

import json
from typing import Any

import httpx
from redis.asyncio import Redis

from orchestrasecai.config import get_settings

settings = get_settings()
CACHE_TTL_SECONDS = 86400


class CveLookupService:
    def __init__(self, redis: Redis | None = None) -> None:
        self.base_url = settings.nvd_api_base_url.rstrip("/")
        self.api_key = settings.nvd_api_key
        self._redis = redis

    async def _get_redis(self) -> Redis:
        if self._redis is None:
            self._redis = Redis.from_url(settings.redis_url)
        return self._redis

    def _cache_key(self, cpe: str) -> str:
        return f"nvd:cpe:{cpe}"

    async def lookup_by_cpe(self, cpe_string: str) -> dict[str, Any]:
        redis = await self._get_redis()
        key = self._cache_key(cpe_string)
        cached = await redis.get(key)
        if cached:
            return json.loads(cached)

        headers: dict[str, str] = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{self.base_url}/cves/2.0",
                params={"cpeName": cpe_string},
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()

        vulns = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            metrics = cve.get("metrics", {})
            cvss = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    cvss = metrics[key][0].get("cvssData", {}).get("baseScore")
                    break
            vulns.append({
                "id": cve.get("id"),
                "description": (cve.get("descriptions") or [{}])[0].get("value", ""),
                "cvss": cvss,
            })

        result = {"cpe": cpe_string, "cves": vulns, "total": len(vulns)}
        await redis.setex(key, CACHE_TTL_SECONDS, json.dumps(result))
        return result
