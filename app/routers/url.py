from fastapi import APIRouter, Request, HTTPException
from app.rate_limit import limiter
from app.models.url import URLResponse
from app.services.aggregator import aggregate_url
from app.cache import get_cached, set_cached

router = APIRouter()

def is_valid_url(url: str) -> bool:
    return url.startswith("http://") or url.startswith("https://")

@router.get("/url", response_model=URLResponse)
@limiter.limit("10/minute")
async def get_url_reputation(url: str, request: Request) -> URLResponse:

    if not is_valid_url(url):
        raise HTTPException(
            status_code=422,
            detail="URL must start with http:// or https://"
        )

    cached = get_cached("url", url)
    if cached:
        return URLResponse(**cached)

    result = await aggregate_url(url)

    successful_sources = len([s for s in result.sources if s.success])
    total_sources = len(result.sources)
    set_cached("url", url, result.model_dump(mode="json"), successful_sources, total_sources)

    return result