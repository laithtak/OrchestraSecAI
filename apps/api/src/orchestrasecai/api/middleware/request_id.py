import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from orchestrasecai.observability.context import bind_context


class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get("X-Request-Id") or str(uuid.uuid4())
        request.state.request_id = rid
        bind_context(request_id=rid)
        response = await call_next(request)
        response.headers["X-Request-Id"] = rid
        return response
