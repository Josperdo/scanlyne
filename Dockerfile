FROM python:3.12-slim-bookworm

# nmap is a system binary — install before copying app code so this
# layer is cached across code-only rebuilds.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source.
COPY . .

# Create the directories that will be volume-mounted at runtime.
# Ownership is set before switching to the non-root user.
RUN mkdir -p instance scans \
    && useradd --system --uid 1001 --no-create-home scanlyne \
    && chown -R scanlyne:scanlyne /app

USER scanlyne

EXPOSE 5000

# Single worker — required for the in-process APScheduler.
CMD ["gunicorn", "--workers", "1", "--bind", "0.0.0.0:5000", "app:create_app()"]
