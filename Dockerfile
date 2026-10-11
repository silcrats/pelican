FROM python:3.13-slim

# System deps:
#   - build-essential/libmagic for document parsing
#   - smbclient for smbcacls (SMB ACL lookups; drop if not crawling SMB)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libmagic1 \
    smbclient \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Pinned with hashes; regenerate from requirements.in with pip-compile
# --generate-hashes after changing it.
COPY requirements.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

COPY pelican ./pelican
COPY crawl_smb.py crawl_exchange.py crawl_sharepoint.py sync_smb_acl.py ./
COPY search_index_mapping.json ./
# Defaults baked in; mount over /app/config (or individual files, or point
# PELICAN_CONFIG / SHARES_CONFIG / EXCHANGE_CONFIG / SHAREPOINT_CONFIG
# elsewhere) to change what's crawled without a rebuild.
COPY config ./config

# Runs as an unprivileged user. Mounted config, secrets and state must be
# readable (state and status: writable) by UID 10001. /state and /status
# are created here so new named volumes come up owned by it.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin pelican \
    && mkdir -p /state /status && chown pelican:pelican /state /status
USER pelican

# One-shot run: crawls once and exits; schedule it externally (e.g. ofelia).
# Pick the job per container with an entrypoint override:
#   python -u crawl_smb.py | crawl_exchange.py | crawl_sharepoint.py | sync_smb_acl.py
ENTRYPOINT ["python", "-u", "crawl_smb.py"]
