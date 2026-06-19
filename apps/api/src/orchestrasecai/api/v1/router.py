from fastapi import APIRouter

from orchestrasecai.api.v1 import auth, findings, health, orgs, policies, projects, reports, scans, targets

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router)
api_router.include_router(auth.router)

from orchestrasecai.api.v1.auth import me as me_endpoint  # noqa: E402

api_router.add_api_route("/me", me_endpoint, methods=["GET"], tags=["auth"])
api_router.include_router(orgs.router)
api_router.include_router(projects.router)
api_router.include_router(targets.router)
api_router.include_router(policies.router)
api_router.include_router(scans.router)
api_router.include_router(findings.router)
api_router.include_router(reports.router)
