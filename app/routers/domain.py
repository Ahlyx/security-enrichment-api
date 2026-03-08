from fastapi import APIRouter, Request, HTTPException
from app.rate_limit import limiter
from app.models.domain import DomainResponse
from app.services.aggregator import aggregate_domain
from app.cache import get_cached, set_cached
from app.utils.validators import is_valid_domain

router = APIRouter()

@router.get("/domain/{name}", response_model=DomainResponse)
@limiter.limit("30/minute")
async def get_domain_reputation(name: str, request: Request) -> DomainResponse:

    if not is_valid_domain(name):
        raise HTTPException(
            status_code=422,
            detail=f"'{name}' is not a valid domain name"
        )

    cached = get_cached("domain", name)
    if cached:
        return DomainResponse(**cached)

    result = await aggregate_domain(name)

    successful_sources = len([s for s in result.sources if s.success])
    total_sources = len(result.sources)
    set_cached("domain", name, result.model_dump(mode="json"), successful_sources, total_sources)

    return result