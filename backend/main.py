from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.analyze import router as analyze_router

app = FastAPI(title="Threat Detection API", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze_router, prefix="/api")


@app.get("/health")
async def health():
    return {"status": "ok"}
