# SilentShift Backend

FastAPI service implementing the SilentShift ITDR detection engine, REST/WebSocket
API and persistence layer. See the [repository README](../README.md) for the full
platform overview and [docs/](../docs) for architecture details.

```bash
pip install -e ".[dev]"
uvicorn app.main:app --reload
```
