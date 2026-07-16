from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import articles, collect, dashboard, health, investigations, logs, settings as settings_routes, summaries, tanium, vulnerabilities
from app.core.config import settings
from app.db.session import create_db
from app.services.scheduler import scheduler_loop


@asynccontextmanager
async def lifespan(_: FastAPI):
    create_db()
    import asyncio

    task = asyncio.create_task(scheduler_loop())
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


app = FastAPI(title=settings.app_name, version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(dashboard.router, prefix="/api")
app.include_router(vulnerabilities.router, prefix="/api")
app.include_router(articles.router, prefix="/api")
app.include_router(collect.router, prefix="/api")
app.include_router(summaries.router, prefix="/api")
app.include_router(logs.router, prefix="/api")
app.include_router(investigations.router, prefix="/api")
app.include_router(tanium.router, prefix="/api")
app.include_router(settings_routes.router, prefix="/api")
