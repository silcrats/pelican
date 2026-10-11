"""
shares.yaml: which SMB shares/folders to crawl, and the environment
variables holding each one's credentials. Shared by the SMB crawler and the
SMB ACL-sync job (and readable by a search UI that downloads straight from
the share, so servers and credentials live in exactly one place).

Loaded on first use rather than at import, so nothing that merely imports
Pelican's SMB helpers needs a shares.yaml to exist.
"""

import os
from functools import lru_cache

from smb.SMBConnection import SMBConnection

from . import settings

SHARES_CONFIG_PATH = settings.config_path("SHARES_CONFIG", "shares.yaml")
SMB_CONNECT_TIMEOUT_SECONDS = int(os.environ.get("SMB_CONNECT_TIMEOUT_SECONDS", "30"))
# NetBIOS name this client announces to the server.
SMB_CLIENT_NAME = os.environ.get("SMB_CLIENT_NAME", "pelican")


@lru_cache(maxsize=None)
def config() -> dict:
    return settings.load_yaml(SHARES_CONFIG_PATH)


def selected_shares() -> list[dict]:
    """Every share in shares.yaml, or only those named in SHARE_NAMES
    (comma-separated). Lets several crawler containers share one shares.yaml
    as the single source of truth while each crawls a different subset in
    parallel. An SMB crawler and its ACL-sync container should use the same
    subset."""
    shares = config().get("shares") or []
    wanted = {n.strip() for n in os.environ.get("SHARE_NAMES", "").split(",") if n.strip()}
    if not wanted:
        return shares
    unknown = wanted - {s["name"] for s in shares}
    if unknown:
        raise ValueError(f"SHARE_NAMES references shares not in {SHARES_CONFIG_PATH}: {sorted(unknown)}")
    return [s for s in shares if s["name"] in wanted]


def credentials(share: dict) -> tuple[str, str, str]:
    """(user, password, domain) for a share, from the environment variables
    its entry (or default_credentials) names."""
    defaults = config().get("default_credentials") or {}
    user_env = share.get("user_env", defaults.get("user_env"))
    pass_env = share.get("pass_env", defaults.get("pass_env"))
    domain_env = share.get("domain_env", defaults.get("domain_env"))
    if not user_env or not pass_env:
        raise KeyError(
            f"Share '{share['name']}' has no user_env/pass_env, and no "
            f"default_credentials block is set in {SHARES_CONFIG_PATH}"
        )
    return os.environ[user_env], os.environ[pass_env], (os.environ.get(domain_env, "") if domain_env else "")


def connect(share: dict) -> SMBConnection:
    user, password, domain = credentials(share)
    conn = SMBConnection(user, password, SMB_CLIENT_NAME, share["server"],
                         domain=domain, use_ntlm_v2=True, is_direct_tcp=True)
    if not conn.connect(share["server"], 445, timeout=SMB_CONNECT_TIMEOUT_SECONDS):
        raise ConnectionError(f"Failed to connect to {share['server']}")
    return conn


def smb_url(share: dict, smb_relative_path: str) -> str:
    """The document url/id for a file: smb://server/share/relative/path."""
    return f"smb://{share['server']}/{share['share']}/{smb_relative_path.replace(chr(92), '/')}"
