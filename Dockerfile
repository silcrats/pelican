FROM python:3.11-slim

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

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY pelican ./pelican
COPY crawl_smb.py crawl_exchange.py crawl_sharepoint.py sync_smb_acl.py ./
COPY search_index_mapping.json ./
# Defaults baked in; mount over /app/config (or individual files, or point
# PELICAN_CONFIG / SHARES_CONFIG / EXCHANGE_CONFIG / SHAREPOINT_CONFIG
# elsewhere) to change what's crawled without a rebuild.
COPY config ./config

# One-shot run: crawls once and exits; schedule it externally (e.g. ofelia).
# Pick the job per container with an entrypoint override:
#   python -u crawl_smb.py | crawl_exchange.py | crawl_sharepoint.py | sync_smb_acl.py
ENTRYPOINT ["python", "-u", "crawl_smb.py"]
