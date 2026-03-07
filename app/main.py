from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import ip

app = FastAPI(
    title="Security Enrichment API",
    description="Aggregates threat intelligence from multiple sources into a single normalized response",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["GET"],
    allow_headers=["*"],
)

app.include_router(ip.router, prefix="/api/v1", tags=["IP Reputation"])

@app.get("/")
async def root():
    return {"message": "Security Enrichment API", "version": "0.1.0", "docs": "/docs"}

@app.get("/health")
async def health():
    return {"status": "ok"}