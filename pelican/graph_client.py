"""
Small Microsoft Graph client shared by the Graph-based crawlers: app-only
sign-in with a client secret, per-thread HTTP sessions, automatic token
refresh, Retry-After-aware retries on throttling, and @odata.nextLink paging.
"""

import os
import threading
import time

import requests


class GraphClient:
    def __init__(self, tenant_env: str, client_id_env: str, secret_env: str,
                 authority: str = "https://login.microsoftonline.com",
                 endpoint: str = "https://graph.microsoft.com/v1.0",
                 scope: str = "https://graph.microsoft.com/.default",
                 max_retries: int = 8, prefer: str | None = None):
        self._env = {"tenant": tenant_env, "client_id": client_id_env, "secret": secret_env}
        self.authority = authority.rstrip("/")
        self.endpoint = endpoint.rstrip("/")
        self.scope = scope
        self.max_retries = max_retries
        self.prefer = prefer
        self._lock = threading.Lock()
        self._token = {"value": None, "expires": 0.0}
        self._local = threading.local()

    def token(self, force: bool = False) -> str:
        with self._lock:
            if force or not self._token["value"] or time.time() > self._token["expires"] - 300:
                # compose passes unset variables through as empty strings, so check
                # for empty rather than missing.
                creds = {k: os.environ.get(name, "").strip() for k, name in self._env.items()}
                missing = [self._env[k] for k, v in creds.items() if not v]
                if missing:
                    raise RuntimeError(
                        f"Missing/empty environment variable(s): {', '.join(missing)} -- "
                        "set them where the container's environment comes from (.env / stack env vars)")
                resp = requests.post(
                    f"{self.authority}/{creds['tenant']}/oauth2/v2.0/token",
                    data={
                        "grant_type": "client_credentials",
                        "client_id": creds["client_id"],
                        "client_secret": creds["secret"],
                        "scope": self.scope,
                    },
                    timeout=30,
                )
                resp.raise_for_status()
                body = resp.json()
                self._token["value"] = body["access_token"]
                self._token["expires"] = time.time() + int(body.get("expires_in", 3600))
            return self._token["value"]

    def _session(self) -> requests.Session:
        if not hasattr(self._local, "session"):
            self._local.session = requests.Session()
        return self._local.session

    def request(self, url: str, params: dict | None = None, stream: bool = False) -> requests.Response:
        """GET with token refresh on 401 and Retry-After-aware backoff on 429/503/504.
        Returns the final response even if it is an error status -- the caller decides."""
        for attempt in range(self.max_retries + 1):
            headers = {"Authorization": f"Bearer {self.token()}"}
            if self.prefer:
                headers["Prefer"] = self.prefer
            try:
                resp = self._session().get(url, params=params, headers=headers, timeout=120, stream=stream)
            except requests.RequestException:
                if attempt == self.max_retries:
                    raise
                time.sleep(min(2 ** attempt, 60))
                continue
            if attempt < self.max_retries:
                if resp.status_code == 401:
                    resp.close()
                    self.token(force=True)
                    continue
                if resp.status_code in (429, 503, 504):
                    try:
                        delay = int(resp.headers.get("Retry-After", 2 ** attempt))
                    except ValueError:
                        delay = 2 ** attempt
                    resp.close()
                    time.sleep(min(delay, 300))
                    continue
            return resp
        raise RuntimeError("unreachable")

    def pages(self, url: str, params: dict | None = None):
        """Yield each page (parsed JSON body) following @odata.nextLink.
        Raises requests.HTTPError on an error status."""
        while url:
            resp = self.request(url, params=params)
            try:
                if not resp.ok:
                    # requests' own HTTPError only carries the status line (e.g.
                    # "403 Client Error: Forbidden for url: ...") -- Graph's actual
                    # error code/message (ErrorAccessDenied, MailboxNotEnabledForRESTAPI,
                    # etc.) is in the response body, and that's almost always the
                    # part that actually explains a failure like this.
                    raise requests.HTTPError(f"{resp.status_code} {resp.reason} for url {resp.url}: {resp.text}", response=resp)
                body = resp.json()
            finally:
                resp.close()
            yield body
            url = body.get("@odata.nextLink")
            params = None  # nextLink already embeds the query
