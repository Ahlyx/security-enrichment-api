from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import ip, domain, url
from app.cache import init_cache
from app.rate_limit import limiter, rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_cache()
    yield

app = FastAPI(
    title="Security Enrichment API",
    description="Aggregates threat intelligence from multiple sources into a single normalized response",
    version="0.1.0",
    lifespan=lifespan
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["GET"],
    allow_headers=["*"],
)

app.include_router(ip.router, prefix="/api/v1", tags=["IP Reputation"])
app.include_router(domain.router, prefix="/api/v1", tags=["Domain Reputation"])
app.include_router(url.router, prefix="/api/v1", tags=["URL Reputation"])

@app.get("/")
async def root():
    return {"message": "Security Enrichment API", "version": "0.1.0", "docs": "/docs"}

@app.get("/health")
async def health():
    return {"status": "ok"}