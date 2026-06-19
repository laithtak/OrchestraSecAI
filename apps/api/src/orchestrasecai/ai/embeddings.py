import hashlib

from orchestrasecai.config import get_settings

settings = get_settings()


def simple_embedding(text: str, dim: int = 64) -> list[float]:
    """Lightweight deterministic embedding for MVP without external model."""
    digest = hashlib.sha256(text.encode()).digest()
    vec = []
    for i in range(dim):
        vec.append((digest[i % len(digest)] / 255.0) * 2 - 1)
    return vec


async def upsert_finding_embedding(org_id: str, finding_id: str, text: str) -> None:
    if not settings.qdrant_enabled:
        return
    try:
        from qdrant_client import QdrantClient
        from qdrant_client.models import Distance, PointStruct, VectorParams

        client = QdrantClient(url=settings.qdrant_url, api_key=settings.qdrant_api_key or None)
        collection = "findings"
        collections = [c.name for c in client.get_collections().collections]
        if collection not in collections:
            client.create_collection(
                collection_name=collection,
                vectors_config=VectorParams(size=64, distance=Distance.COSINE),
            )
        client.upsert(
            collection_name=collection,
            points=[
                PointStruct(
                    id=finding_id,
                    vector=simple_embedding(text),
                    payload={"org_id": org_id, "finding_id": finding_id},
                )
            ],
        )
    except Exception:
        pass


async def find_similar(org_id: str, text: str, limit: int = 3) -> list[dict]:
    if not settings.qdrant_enabled:
        return []
    try:
        from qdrant_client import QdrantClient

        client = QdrantClient(url=settings.qdrant_url, api_key=settings.qdrant_api_key or None)
        results = client.search(
            collection_name="findings",
            query_vector=simple_embedding(text),
            limit=limit,
            query_filter={"must": [{"key": "org_id", "match": {"value": org_id}}]},
        )
        return [{"finding_id": r.payload.get("finding_id"), "score": r.score} for r in results]
    except Exception:
        return []
