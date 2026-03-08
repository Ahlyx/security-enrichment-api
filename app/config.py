from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    abuseipdb_api_key: str = ""
    virustotal_api_key: str = ""
    ipinfo_api_key: str = ""
    otx_api_key: str = ""
    google_safe_browsing_api_key: str = ""
    urlscan_api_key: str = ""
    malwarebazaar_api_key: str = ""
    
    cache_ttl_seconds: int = 3600  # 1 hour
    rate_limit: str = "30/minute"
    
    class Config:
        env_file = ".env"

settings = Settings()