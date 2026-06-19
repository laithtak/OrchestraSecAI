import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from orchestrasecai.observability.context import bind_request_context, clear_context
from orchestrasecai.observability.logging import get_logger

logger = get_logger(__name__)


class AccessLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        bind_request_context(request)
        start = time.perf_counter()
        try:
            response = await call_next(request)
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            logger.info(
                "request_completed",
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                duration_ms=duration_ms,
            )
            return response
        finally:
            clear_context()
