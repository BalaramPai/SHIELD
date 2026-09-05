# File: apps/api/main.py
# Purpose: Creates the SHIELD FastAPI application and registers all API routes.

from fastapi import FastAPI

from apps.api.routes import router


app = FastAPI(
    title="SHIELD API",
    description="Backend API for the SHIELD network security platform.",
    version="0.2.0",
)

app.include_router(router)