from orchestrasecai.persistence.tables.core import UserRole

ROLE_PERMISSIONS: dict[UserRole, set[str]] = {
    UserRole.owner: {
        "scans:read",
        "scans:write",
        "targets:read",
        "targets:write",
        "projects:read",
        "projects:write",
        "policies:read",
        "policies:write",
        "org:read",
        "org:write",
        "users:read",
        "users:write",
        "findings:write",
        "reports:read",
    },
    UserRole.admin: {
        "scans:read",
        "scans:write",
        "targets:read",
        "targets:write",
        "projects:read",
        "projects:write",
        "policies:read",
        "policies:write",
        "org:read",
        "users:read",
        "users:write",
        "findings:write",
        "reports:read",
    },
    UserRole.analyst: {
        "scans:read",
        "scans:write",
        "targets:read",
        "projects:read",
        "policies:read",
        "findings:write",
        "reports:read",
    },
    UserRole.viewer: {
        "scans:read",
        "targets:read",
        "projects:read",
        "policies:read",
        "reports:read",
    },
}


def has_permission(role: UserRole, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, set())


def require_permission(role: UserRole, permission: str) -> None:
    if not has_permission(role, permission):
        from fastapi import HTTPException

        raise HTTPException(status_code=403, detail=f"Permission denied: {permission}")
