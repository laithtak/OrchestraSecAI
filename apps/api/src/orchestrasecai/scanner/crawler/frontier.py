from collections import deque


class Frontier:
    def __init__(self) -> None:
        self._queue: deque[tuple[str, int, str | None]] = deque()
        self._seen: set[str] = set()

    def add(self, url: str, depth: int, parent: str | None = None) -> bool:
        if url in self._seen:
            return False
        self._seen.add(url)
        self._queue.append((url, depth, parent))
        return True

    def pop(self) -> tuple[str, int, str | None] | None:
        if not self._queue:
            return None
        return self._queue.popleft()

    def __len__(self) -> int:
        return len(self._queue)
