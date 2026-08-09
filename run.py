import sys
import os
import uvicorn

# Ensure backend package is in python sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(BASE_DIR, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

if __name__ == "__main__":
    print("=" * 70)
    print("  SilentShift: Context-Aware Behavioral Security & Threat Transition")
    print("=" * 70)
    print("  Starting analytical engine and web interface on:")
    print("  --> http://127.0.0.1:8000")
    print("=" * 70)
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=False, log_level="info")
