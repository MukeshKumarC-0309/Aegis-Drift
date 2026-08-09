import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from app.api.routes import router as api_router

app = FastAPI(
    title="SilentShift - Behavioral Security & Threat Transition Platform",
    description="Context-Aware Behavioral Anomaly Detection & Threat Transition Analytics",
    version="1.0.0"
)

# Enable CORS for local dev and cross-origin clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(api_router, prefix="/api")

# Determine frontend directory
current_dir = os.path.dirname(os.path.abspath(__file__))
frontend_dir = os.path.abspath(os.path.join(current_dir, "..", "..", "frontend"))

if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

    @app.get("/")
    async def serve_index():
        index_file = os.path.join(frontend_dir, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return {"message": "Frontend index.html not found yet."}
else:
    @app.get("/")
    async def root():
        return {"message": "SilentShift API is running. Frontend directory not found."}


@app.get("/health")
def health():
    return {"status": "healthy", "service": "SilentShift-Analytics"}
