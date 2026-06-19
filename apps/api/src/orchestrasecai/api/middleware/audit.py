import re

from uuid import UUID



from jose import JWTError

from starlette.middleware.base import BaseHTTPMiddleware

from starlette.requests import Request



from orchestrasecai.api.services.audit import log_audit

from orchestrasecai.observability.logging import get_logger

from orchestrasecai.persistence.session import async_session_factory

from orchestrasecai.security.auth import decode_token



logger = get_logger(__name__)



_UUID_RE = re.compile(

    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",

    re.IGNORECASE,

)





def _derive_audit_record(request: Request, status_code: int) -> dict | None:

    record = getattr(request.state, "audit_record", None)

    if record:

        metadata = dict(record.get("metadata") or {})

        metadata["status"] = status_code

        return {**record, "metadata": metadata}



    auth = request.headers.get("Authorization", "")

    if not auth.startswith("Bearer "):

        return None



    try:

        payload = decode_token(auth[7:])

        if payload.get("type") != "access":

            return None

        user_id = UUID(payload["sub"])

        org_id = UUID(payload["org_id"])

    except (JWTError, KeyError, ValueError):

        return None



    path = request.url.path

    parts = [p for p in path.split("/") if p and p != "api" and p != "v1"]

    resource_type = parts[0] if parts else "api"

    resource_id = None

    for part in reversed(parts):

        if _UUID_RE.fullmatch(part):

            resource_id = part

            break



    return {

        "org_id": org_id,

        "user_id": user_id,

        "action": f"{request.method.lower()}.{resource_type}",

        "resource_type": resource_type,

        "resource_id": resource_id,

        "metadata": {"status": status_code, "path": path},

    }





class AuditMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next):

        response = await call_next(request)

        if request.method not in ("POST", "PATCH", "DELETE") or not request.url.path.startswith("/api/v1"):

            return response



        request.state.audit_pending = {

            "path": request.url.path,

            "method": request.method,

            "status": response.status_code,

        }



        try:

            record = _derive_audit_record(request, response.status_code)

            if not record or not record.get("org_id"):

                return response



            async with async_session_factory() as session:

                await log_audit(

                    session,

                    record["org_id"],

                    record.get("user_id"),

                    record["action"],

                    record["resource_type"],

                    record.get("resource_id"),

                    request.client.host if request.client else None,

                    request.headers.get("user-agent"),

                    record.get("metadata"),

                )

                await session.commit()

        except Exception as exc:

            logger.warning(

                "audit_persistence_failed",

                method=request.method,

                path=request.url.path,

                error=str(exc),

            )



        return response

