from urllib.parse import urlparse
from urllib.robotparser import RobotFileParser

import httpx

from orchestrasecai.security.passive_http import assert_passive_method


class RobotsCache:
    def __init__(self) -> None:
        self._parsers: dict[str, RobotFileParser] = {}

    async def fetch(self, client: httpx.AsyncClient, base_url: str, user_agent: str) -> RobotFileParser:
        parsed = urlparse(base_url)
        key = f"{parsed.scheme}://{parsed.netloc}"
        if key in self._parsers:
            return self._parsers[key]
        rp = RobotFileParser()
        robots_url = f"{key}/robots.txt"
        try:
            assert_passive_method("GET")
            resp = await client.get(robots_url, timeout=10.0)
            if resp.status_code == 200:
                rp.parse(resp.text.splitlines())
            else:
                rp.allow_all = True
        except Exception:
            rp.allow_all = True
        self._parsers[key] = rp
        return rp

    def can_fetch(self, rp: RobotFileParser, user_agent: str, url: str) -> bool:
        try:
            return rp.can_fetch(user_agent, url)
        except Exception:
            return True
