# Aegis Drift Backend

FastAPI service implementing the Aegis Drift ITDR detection engine, REST/WebSocket
API and persistence layer. See the [repository README](../README.md) for the full
platform overview and [docs/](../docs) for architecture details.

```bash
pip install -e ".[dev]"
uvicorn app.main:app --reload
```
