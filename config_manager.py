import asyncio
import logging
import httpx
from typing import Dict, Optional
from pydantic import BaseModel

from config import settings

logger = logging.getLogger("worker.config")


# =========================
# Project config (worker)
# =========================

class ProjectConfig(BaseModel):
    project_id: str
    upstream_base_url: str
    api_key_hash: str


class ConfigManager:
    _instance = None

    def __init__(self):
        self._projects_by_key: Dict[str, ProjectConfig] = {}
        self._lock = asyncio.Lock()

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def start_background_refresh(self):
        asyncio.create_task(self._refresh_loop())

    async def _refresh_loop(self):
        logger.info("Starting config refresh loop...")
        while True:
            try:
                await self._fetch_and_update()
            except Exception as e:
                logger.error(f"Config refresh failed (retrying in 60s): {e}")
            await asyncio.sleep(60)

    async def _fetch_and_update(self):
        url = f"{settings.CONTROL_API_BASE_URL}/internal/worker/config"

        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                url,
                headers={
                    "x-control-secret": settings.CONTROL_WORKER_SHARED_SECRET
                },
            )
            resp.raise_for_status()
            data = resp.json()

        new_map: Dict[str, ProjectConfig] = {}

        for project in data.get("projects", []):
            # ONE key per project (by your design)
            api_key_hash = project["api_keys"][0]

            new_map[api_key_hash] = ProjectConfig(
                project_id=str(project["id"]),
                upstream_base_url=project["upstream_url"],
                api_key_hash=api_key_hash,
            )

        async with self._lock:
            self._projects_by_key = new_map

        logger.info(f"Loaded {len(new_map)} project configs")

    def get_project_by_key(self, api_key_hash: str) -> Optional[ProjectConfig]:
        return self._projects_by_key.get(api_key_hash)


# Singleton
config_manager = ConfigManager.get_instance()
