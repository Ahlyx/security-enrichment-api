from fastapi import APIRouter, Request, HTTPException
from app.rate_limit import limiter
from app.models.ip import IPResponse
from app.services.aggregator import aggregate_ip
from app.cache import get_cached, set_cached
from app.utils.validators import is_valid_ip, is_private_ip

router = APIRouter()

@router.get("/ip/{address}", response_model=IPResponse)
@limiter.limit("30/minute")
async def get_ip_reputation(address: str, request: Request) -> IPResponse:

    if not is_valid_ip(address):
        raise HTTPException(
            status_code=422,
            detail=f"'{address}' is not a valid IP address"
        )

    if is_private_ip(address):
        raise HTTPException(
            status_code=400,
            detail=f"'{address}' is a private IP address. Only public IPs are supported."
        )

    cached = get_cached("ip", address)
    if cached:
        return IPResponse(**cached)

    result = await aggregate_ip(address)

    successful_sources = len([s for s in result.sources if s.success])
    total_sources = len(result.sources)
    set_cached("ip", address, result.model_dump(mode="json"), successful_sources, total_sources)

    return result