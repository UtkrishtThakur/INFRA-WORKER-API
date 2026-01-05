from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    # =========================
    # Environment
    # =========================
    ENV: str = Field(default="dev")

    # =========================
    # Database (PostgreSQL) - REMOVED for Stateless Worker
    # =========================

    # =========================
    # Redis (rate limits, ML state)
    # =========================
    REDIS_URL: str

    # =========================
    # Control API (management plane)
    # =========================
    CONTROL_API_BASE_URL: str
    CONTROL_WORKER_SHARED_SECRET: str

    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore"


# Singleton
settings = Settings()
