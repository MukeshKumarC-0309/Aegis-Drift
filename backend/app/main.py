import os
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
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

    @app.get("/404", include_in_schema=False)
    async def serve_404():
        page_404 = os.path.join(frontend_dir, "404.html")
        if os.path.exists(page_404):
            return FileResponse(page_404, status_code=404)
        return JSONResponse(status_code=404, content={"error": "404 page not found"})

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon():
        ico_file = os.path.join(frontend_dir, "favicon.ico")
        if os.path.exists(ico_file):
            return FileResponse(ico_file, media_type="image/x-icon")
        svg_file = os.path.join(frontend_dir, "favicon.svg")
        if os.path.exists(svg_file):
            return FileResponse(svg_file, media_type="image/svg+xml")
        return JSONResponse(status_code=404, content={"message": "Favicon not found"})
else:
    @app.get("/")
    async def root():
        return {"message": "SilentShift API is running. Frontend directory not found."}


@app.get("/health")
def health():
    return {"status": "healthy", "service": "SilentShift-Analytics"}


@app.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 404:
        if request.url.path.startswith("/api"):
            return JSONResponse(
                status_code=404,
                content={"error": "API route not found", "path": request.url.path, "status": 404}
            )
        page_404 = os.path.join(frontend_dir, "404.html")
        if os.path.exists(page_404):
            return FileResponse(page_404, status_code=404)
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail}
    )
