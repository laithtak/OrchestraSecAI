from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from orchestrasecai.persistence.tables import AuditLog


async def write_audit_log(
    db: AsyncSession,
    *,
    org_id: UUID,
    user_id: UUID | None,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    metadata: dict | None = None,
) -> None:
    log = AuditLog(
        org_id=org_id,
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=ip_address,
        user_agent=user_agent,
        metadata_=metadata or {},
    )
    db.add(log)
    await db.flush()
