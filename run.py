import sys
import os
import uvicorn

# Ensure backend package is in python sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(BASE_DIR, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    print("=" * 70)
    print("  SilentShift: Context-Aware Behavioral Security & Threat Transition")
    print("=" * 70)
    print("  Starting analytical engine and web interface on:")
    print(f"  --> http://{host}:{port}")
    print("=" * 70)
    uvicorn.run("app.main:app", host=host, port=port, reload=False, log_level="info")
