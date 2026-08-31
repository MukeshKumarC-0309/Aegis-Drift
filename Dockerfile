# Multi-stage lightweight Python container for SilentShift ITDR Platform
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Expose HTTP port
EXPOSE 8000

# Set environment
ENV PYTHONPATH=/app/backend
ENV PYTHONUNBUFFERED=1

# Start enterprise server
CMD ["python", "run.py"]
