from fastapi import APIRouter, Request, HTTPException
from app.rate_limit import limiter
from app.models.hash import HashResponse
from app.services.aggregator import aggregate_hash
from app.cache import get_cached, set_cached
from app.utils.validators import is_valid_hash

router = APIRouter()

@router.get("/hash/{hash_value}", response_model=HashResponse)
@limiter.limit("30/minute")
async def get_hash_reputation(hash_value: str, request: Request) -> HashResponse:

    hash_value = hash_value.strip().lower()

    if not is_valid_hash(hash_value):
        raise HTTPException(
            status_code=422,
            detail="Invalid hash. Must be a valid MD5 (32), SHA1 (40), or SHA256 (64) hex string."
        )

    cached = get_cached("hash", hash_value)
    if cached:
        return HashResponse(**cached)

    result = await aggregate_hash(hash_value)

    successful_sources = len([s for s in result.sources if s.success])
    total_sources = len(result.sources)
    set_cached("hash", hash_value, result.model_dump(mode="json"), successful_sources, total_sources)

    return result