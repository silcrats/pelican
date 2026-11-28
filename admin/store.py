"""
The admin portal's data: sources, scopes, credential profiles, per-type
settings, jobs, workers and the audit log, in one SQLite file. Also the
rules for who may change what, the job scheduler, and rendering sources
back into the YAML the crawlers read.

Nothing here holds a secret. A source names the environment variables
that hold its credentials (through a credential profile), exactly as the
YAML files do; the workers that run the crawlers have the values.

Delegation:
  - Super admins (members of an SUPER_ADMIN_GROUPS group) can do everything.
  - A scope gives the AD groups listed on it control of the sources in that
    scope, within the scope's limits: which source types, which SMB servers
    and credential profiles, which extra access grants, and the shortest
    schedule. A source's documents can only ever be made visible to people
    a super admin allowed for that scope, and the crawl account's
    credentials can only be sent to servers a super admin listed.
"""

import copy
import json
import re
import sqlite3
import threading
import time

import yaml

KINDS = ("smb", "exchange", "sharepoint")
JOB_TYPES = ("crawl", "acl", "test", "purge")
# Each kind's YAML file, the key holding its list of sources, and the
# variable that picks a subset of that list.
KIND_INFO = {
    "smb": {"label": "SMB share", "file": "shares.yaml", "list_key": "shares",
            "names_env": "SHARE_NAMES", "config_env": "SHARES_CONFIG"},
    "exchange": {"label": "Exchange mailbox", "file": "exchange.yaml", "list_key": "mailboxes",
                 "names_env": "MAILBOX_NAMES", "config_env": "EXCHANGE_CONFIG"},
    "sharepoint": {"label": "SharePoint site", "file": "sharepoint.yaml", "list_key": "sites",
                   "names_env": "SITE_NAMES", "config_env": "SHAREPOINT_CONFIG"},
}

# Per-source fields. "fixed": decides which documents belong to the source,
# so it can't change after creation (the old documents would be left
# behind); add a new source and remove the old one instead. "super_admin":
# only a super admin may set it, because it can widen who sees the documents.
TEXT, BOOL, INT, LIST, DATE, CHOICE = "text", "bool", "int", "list", "date", "choice"
FIELDS = {
    "smb": {
        "server": {"type": TEXT, "required": True, "fixed": True},
        "share": {"type": TEXT, "required": True, "fixed": True},
        "path": {"type": TEXT, "fixed": True},
        "encrypt": {"type": BOOL},
        "acl_scope": {"type": CHOICE, "choices": ["directory", "file"]},
        "exclude_extensions": {"type": LIST},
        "exclude_no_extension": {"type": BOOL},
    },
    "exchange": {
        "user": {"type": TEXT, "required": True, "fixed": True},
        "since": {"type": DATE},
        "exclude_folders": {"type": LIST},
        "full_access": {"type": BOOL},
        "archive": {"type": BOOL, "fixed": True},
    },
    "sharepoint": {
        "url": {"type": TEXT, "required": True, "fixed": True},
        "libraries": {"type": LIST},
        "exclude_libraries": {"type": LIST},
        "include_extensions": {"type": LIST},
        "exclude_extensions": {"type": LIST},
        "exclude_no_extension": {"type": BOOL},
        "since": {"type": DATE},
        "group": {"type": TEXT, "super_admin": True},
        "mirror_members": {"type": BOOL},
    },
}
# Hand-written access grants (`permissions:`); SMB access comes from the
# share's own ACLs only.
HAS_PERMISSIONS = {"smb": False, "exchange": True, "sharepoint": True}
GRANT_KINDS = ("users", "groups", "roles")
# SMB credentials come from a credential profile; Graph sources use the
# one app registration in their type's settings.
CREDENTIAL_FIELDS = ("user_env", "pass_env", "domain_env")
DEFAULT_CREDENTIALS = "default"   # the profile name meaning default_credentials

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
ENV_RE = re.compile(r"^[A-Z_][A-Z0-9_]{0,63}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")

MIN_INTERVAL_MINUTES = 5          # the shortest schedule anyone can set
DEFAULT_SCOPE_MIN_MINUTES = 60    # a new scope's shortest schedule
LEASE_SECONDS = 120               # a running job with no heartbeat for this long has lost its worker
DEFAULT_WORKER_SLOTS = 2         # jobs a worker runs at once, unless a super admin changes it
INDEX_JOBS_KEPT = 50
# Index jobs (see rebuild_index.py). Those that change which index searches
# use hold every crawl, ACL sync and removal until they end, so nothing is
# written to the index meanwhile; they start once none is running.
INDEX_ACTIONS = ("check", "rebuild", "switch_back", "drop_previous", "tidy")
HOLDING_ACTIONS = ("rebuild", "switch_back")
# Vector settings a rebuild uses, until a super admin saves others. The
# embeddings server and model default to the portal's EMBEDDINGS_URL and
# EMBEDDINGS_MODEL (as in config/pelican.yaml).
VECTOR_DEFAULTS = {"enabled": False, "embeddings_url": "http://embeddings/embed",
                   "model": "BAAI/bge-base-en-v1.5", "chunk_words": 300, "chunk_overlap": 0.1, "max_chunks": 100}
URL_RE = re.compile(r"^https?://[A-Za-z0-9.-]+(:\d{1,5})?(/[^\s]*)?$")
MAX_WORKER_SLOTS = 16
WORKER_FORGET_SECONDS = 3600     # a worker not heard from for this long leaves the list
PURGE_RETRY_SECONDS = 300        # a failed removal is tried again after this
JOB_LOG_CHARS = 20000             # log tail kept per job
JOBS_KEPT_PER_SOURCE = 50
AUDIT_KEPT = 20000

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS scopes (
    id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, kind TEXT NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS settings (kind TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    name TEXT UNIQUE NOT NULL,
    scope_id INTEGER,
    enabled INTEGER NOT NULL DEFAULT 1,
    removing INTEGER NOT NULL DEFAULT 0,
    config TEXT NOT NULL,
    credential TEXT,
    crawl_minutes INTEGER NOT NULL DEFAULT 0,
    acl_minutes INTEGER NOT NULL DEFAULT 0,
    position REAL NOT NULL DEFAULT 0,
    created_at REAL, created_by TEXT, updated_at REAL, updated_by TEXT);
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    status TEXT NOT NULL,
    requested_by TEXT,
    created_at REAL, started_at REAL, finished_at REAL,
    worker TEXT, lease_until REAL, cancel INTEGER NOT NULL DEFAULT 0,
    exit_code INTEGER, log TEXT, summary TEXT);
CREATE INDEX IF NOT EXISTS jobs_by_source ON jobs (source_id, type, status);
CREATE INDEX IF NOT EXISTS jobs_by_status ON jobs (status, created_at);
CREATE TABLE IF NOT EXISTS workers (
    name TEXT PRIMARY KEY, last_seen REAL, slots INTEGER, running INTEGER, version TEXT);
-- Super admins' per-worker settings; kept when a worker leaves the list.
CREATE TABLE IF NOT EXISTS worker_settings (name TEXT PRIMARY KEY, slots INTEGER);
-- Index jobs (Index page): not about one source, so kept apart from jobs.
CREATE TABLE IF NOT EXISTS index_jobs (
    id INTEGER PRIMARY KEY,
    action TEXT NOT NULL,
    op TEXT NOT NULL,
    status TEXT NOT NULL,
    requested_by TEXT,
    created_at REAL, started_at REAL, finished_at REAL,
    worker TEXT, lease_until REAL, cancel INTEGER NOT NULL DEFAULT 0,
    exit_code INTEGER, log TEXT, summary TEXT);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY, at REAL, user TEXT, action TEXT,
    scope_id INTEGER, target TEXT, detail TEXT);
"""


class Invalid(ValueError):
    """A request that breaks a rule; the message is shown to the user."""


class Forbidden(Exception):
    """The signed-in user may not do this."""


class NotFound(Exception):
    pass


class User:
    """A signed-in person: their AD username and group CNs."""

    def __init__(self, username: str, groups, display_name: str = "", super_admin: bool = False):
        self.username = username
        self.groups = {g.lower() for g in groups}
        self.display_name = display_name or username
        self.super_admin = super_admin

    def in_any(self, groups) -> bool:
        return any(g.lower() in self.groups for g in groups or [])


def _clean_list(value, what: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = [v for v in re.split(r"[,\n]", value)]
    if not isinstance(value, list):
        raise Invalid(f"{what} must be a list")
    out = []
    for v in value:
        if not isinstance(v, (str, int, float)) or isinstance(v, bool):
            raise Invalid(f"{what} must be a list of text values")
        v = str(v).strip()
        if v and v not in out:
            out.append(v)
    return out


def _dump_yaml(data) -> str:
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True, default_flow_style=False)


class Store:
    def __init__(self, path: str, admin_groups=(), defaults: dict | None = None,
                 vector_defaults: dict | None = None):
        self.path = path
        self.vector_defaults = {**VECTOR_DEFAULTS, **(vector_defaults or {})}
        self.admin_groups = [g for g in admin_groups if g]
        self.defaults = {"crawl_minutes": 360, "acl_minutes": 120}
        self.defaults.update(defaults or {})
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False, timeout=30)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript(SCHEMA)
        self.db.commit()
        # Called after anything a rendered YAML export depends on changes.
        self.on_change = lambda: None

    # ----------------------------------------------------------- helpers

    def _q(self, sql, args=()):
        return self.db.execute(sql, args).fetchall()

    def _one(self, sql, args=()):
        return self.db.execute(sql, args).fetchone()

    def meta(self, key, default=None):
        row = self._one("SELECT value FROM meta WHERE key = ?", (key,))
        return row["value"] if row else default

    def set_meta(self, key, value):
        self.db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))

    def audit(self, user: str, action: str, target: str = "", scope_id=None, detail=None):
        self.db.execute(
            "INSERT INTO audit (at, user, action, scope_id, target, detail) VALUES (?, ?, ?, ?, ?, ?)",
            (time.time(), user, action, scope_id, target, json.dumps(detail) if detail is not None else None))
        self.db.execute("DELETE FROM audit WHERE id <= (SELECT MAX(id) FROM audit) - ?", (AUDIT_KEPT,))

    def user(self, username: str, groups, display_name: str = "") -> User:
        u = User(username, groups, display_name)
        u.super_admin = u.in_any(self.admin_groups)
        return u

    def may_sign_in(self, user: User) -> bool:
        """Super admins, and members of a group some scope delegates to."""
        return user.super_admin or bool(self._managed_scope_ids(user))

    # ------------------------------------------------------------ scopes

    def _scope_row(self, row) -> dict:
        data = json.loads(row["data"])
        return {"id": row["id"], "name": row["name"], **data}

    def scopes(self) -> list[dict]:
        return [self._scope_row(r) for r in self._q("SELECT * FROM scopes ORDER BY name COLLATE NOCASE")]

    def scope(self, scope_id) -> dict:
        row = self._one("SELECT * FROM scopes WHERE id = ?", (scope_id,))
        if not row:
            raise NotFound("no such scope")
        return self._scope_row(row)

    def _managed_scope_ids(self, user: User) -> set[int]:
        return {s["id"] for s in self.scopes() if user.in_any(s["groups"])}

    def visible_scopes(self, user: User) -> list[dict]:
        if user.super_admin:
            return self.scopes()
        ids = self._managed_scope_ids(user)
        return [s for s in self.scopes() if s["id"] in ids]

    def _validate_scope(self, body: dict) -> tuple[str, dict]:
        name = str(body.get("name") or "").strip()
        if not name or len(name) > 80:
            raise Invalid("a scope needs a name of up to 80 characters")
        kinds = _clean_list(body.get("kinds"), "Source types")
        if any(k not in KINDS for k in kinds):
            raise Invalid("unknown source type")
        servers = [s.lower() for s in _clean_list(body.get("smb_servers"), "SMB servers")]
        for s in servers:
            if not HOST_RE.match(s):
                raise Invalid(f"not a server name: {s}")
        creds = _clean_list(body.get("credentials"), "Credential profiles")
        known = {c["name"] for c in self.credentials()} | {DEFAULT_CREDENTIALS}
        unknown = [c for c in creds if c not in known]
        if unknown:
            raise Invalid(f"no such credential profile: {', '.join(unknown)}")
        try:
            min_minutes = int(body.get("min_minutes") or DEFAULT_SCOPE_MIN_MINUTES)
        except (TypeError, ValueError):
            raise Invalid("the shortest schedule must be a number of minutes")
        data = {
            "groups": _clean_list(body.get("groups"), "Managed by"),
            "kinds": kinds,
            "smb_servers": servers,
            "credentials": creds,
            "grant_users": [u.lower() for u in _clean_list(body.get("grant_users"), "Users")],
            "grant_groups": _clean_list(body.get("grant_groups"), "Groups"),
            "grant_roles": _clean_list(body.get("grant_roles"), "Roles"),
            "min_minutes": max(MIN_INTERVAL_MINUTES, min_minutes),
            "note": str(body.get("note") or "")[:1000],
        }
        if not data["groups"]:
            raise Invalid("name at least one AD group that manages this scope")
        return name, data

    def save_scope(self, user: User, body: dict, scope_id=None) -> dict:
        if not user.super_admin:
            raise Forbidden()
        name, data = self._validate_scope(body)
        with self.lock:
            clash = self._one("SELECT id FROM scopes WHERE name = ? COLLATE NOCASE AND id IS NOT ?", (name, scope_id))
            if clash:
                raise Invalid("a scope with that name already exists")
            if scope_id is None:
                cur = self.db.execute("INSERT INTO scopes (name, data) VALUES (?, ?)", (name, json.dumps(data)))
                scope_id = cur.lastrowid
                self.audit(user.username, "scope created", name, scope_id, data)
            else:
                before = self.scope(scope_id)
                self.db.execute("UPDATE scopes SET name = ?, data = ? WHERE id = ?", (name, json.dumps(data), scope_id))
                self.audit(user.username, "scope changed", name, scope_id,
                           {"before": {k: v for k, v in before.items() if k != "id"}, "after": {"name": name, **data}})
            self.db.commit()
            return self.scope(scope_id)

    def delete_scope(self, user: User, scope_id) -> None:
        if not user.super_admin:
            raise Forbidden()
        with self.lock:
            scope = self.scope(scope_id)
            if self._one("SELECT 1 FROM sources WHERE scope_id = ?", (scope_id,)):
                raise Invalid("move or remove this scope's sources first")
            self.db.execute("DELETE FROM scopes WHERE id = ?", (scope_id,))
            self.audit(user.username, "scope deleted", scope["name"], scope_id)
            self.db.commit()

    # ------------------------------------------------ credential profiles

    def credentials(self) -> list[dict]:
        return [{"id": r["id"], "name": r["name"], "kind": r["kind"], **json.loads(r["data"])}
                for r in self._q("SELECT * FROM credentials ORDER BY name COLLATE NOCASE")]

    def credential(self, name: str) -> dict | None:
        return next((c for c in self.credentials() if c["name"] == name), None)

    def save_credential(self, user: User, body: dict, cred_id=None) -> dict:
        if not user.super_admin:
            raise Forbidden()
        name = str(body.get("name") or "").strip()
        if not NAME_RE.match(name) or name == DEFAULT_CREDENTIALS:
            raise Invalid("a profile name is letters, digits, '.', '_' or '-', and not 'default'")
        data = {}
        for field in CREDENTIAL_FIELDS:
            value = str(body.get(field) or "").strip()
            if field != "domain_env" and not value:
                raise Invalid(f"{field} is required")
            if value and not ENV_RE.match(value):
                raise Invalid(f"{field} must be an environment variable name, like SMB_PASS_ENG")
            data[field] = value
        data["note"] = str(body.get("note") or "")[:500]
        with self.lock:
            if self._one("SELECT id FROM credentials WHERE name = ? AND id IS NOT ?", (name, cred_id)):
                raise Invalid("a profile with that name already exists")
            if cred_id is None:
                cur = self.db.execute("INSERT INTO credentials (name, kind, data) VALUES (?, 'smb', ?)",
                                      (name, json.dumps(data)))
                cred_id = cur.lastrowid
                self.audit(user.username, "credential profile created", name, None, data)
            else:
                old = self._one("SELECT name FROM credentials WHERE id = ?", (cred_id,))
                if not old:
                    raise NotFound("no such profile")
                if old["name"] != name:
                    raise Invalid("a profile can't be renamed; sources and scopes refer to it by name")
                self.db.execute("UPDATE credentials SET data = ? WHERE id = ?", (json.dumps(data), cred_id))
                self.audit(user.username, "credential profile changed", name, None, data)
            self.db.commit()
        self.on_change()
        return self.credential(name)

    def delete_credential(self, user: User, cred_id) -> None:
        if not user.super_admin:
            raise Forbidden()
        with self.lock:
            row = self._one("SELECT name FROM credentials WHERE id = ?", (cred_id,))
            if not row:
                raise NotFound("no such profile")
            if self._one("SELECT 1 FROM sources WHERE credential = ?", (row["name"],)):
                raise Invalid("sources still use this profile")
            if any(row["name"] in s["credentials"] for s in self.scopes()):
                raise Invalid("a scope still allows this profile; take it off the scope first")
            self.db.execute("DELETE FROM credentials WHERE id = ?", (cred_id,))
            self.audit(user.username, "credential profile deleted", row["name"])
            self.db.commit()

    # -------------------------------------------------------- settings

    def settings(self, kind: str) -> dict:
        row = self._one("SELECT data FROM settings WHERE kind = ?", (kind,))
        return json.loads(row["data"]) if row else {}

    def save_settings(self, user: User, kind: str, text: str) -> dict:
        """A type's global settings (everything in its YAML file except the
        source list), edited as YAML by a super admin."""
        if not user.super_admin:
            raise Forbidden()
        if kind not in KINDS:
            raise NotFound("no such source type")
        try:
            data = yaml.safe_load(text) if text.strip() else {}
        except yaml.YAMLError as exc:
            raise Invalid(f"not valid YAML: {exc}")
        if not isinstance(data, dict):
            raise Invalid("settings must be a YAML mapping")
        list_key = KIND_INFO[kind]["list_key"]
        if list_key in data:
            raise Invalid(f"sources are managed on the Sources page; remove `{list_key}:`")
        with self.lock:
            before = self.settings(kind)
            self.db.execute("INSERT OR REPLACE INTO settings (kind, data) VALUES (?, ?)", (kind, json.dumps(data)))
            self.audit(user.username, "settings changed", kind, None, {"before": before, "after": data})
            self.db.commit()
        self.on_change()
        return data

    # --------------------------------------------------------- sources

    def _source_row(self, row) -> dict:
        return {
            "id": row["id"], "kind": row["kind"], "name": row["name"], "scope_id": row["scope_id"],
            "enabled": bool(row["enabled"]), "removing": bool(row["removing"]),
            "config": json.loads(row["config"]), "credential": row["credential"],
            "crawl_minutes": row["crawl_minutes"], "acl_minutes": row["acl_minutes"],
            "created_at": row["created_at"], "created_by": row["created_by"],
            "updated_at": row["updated_at"], "updated_by": row["updated_by"],
        }

    def all_sources(self, kind: str | None = None) -> list[dict]:
        sql = "SELECT * FROM sources" + (" WHERE kind = ?" if kind else "") + " ORDER BY position, id"
        return [self._source_row(r) for r in self._q(sql, (kind,) if kind else ())]

    def source(self, source_id) -> dict:
        row = self._one("SELECT * FROM sources WHERE id = ?", (source_id,))
        if not row:
            raise NotFound("no such source")
        return self._source_row(row)

    def may_manage(self, user: User, source: dict) -> bool:
        return user.super_admin or source["scope_id"] in self._managed_scope_ids(user)

    def visible_sources(self, user: User) -> list[dict]:
        if user.super_admin:
            return self.all_sources()
        ids = self._managed_scope_ids(user)
        return [s for s in self.all_sources() if s["scope_id"] in ids]

    def managed_source(self, user: User, source_id) -> dict:
        source = self.source(source_id)
        if not self.may_manage(user, source):
            raise NotFound("no such source")   # don't reveal it exists
        return source

    def _validate_fields(self, kind: str, given: dict, before: dict | None, user: User) -> dict:
        """The source's config from the form: known fields only, typed, with
        fixed fields unchanged on an edit. Fields an import carried that the
        form doesn't know about are kept as they were."""
        fields = FIELDS[kind]
        if not isinstance(given, dict):
            raise Invalid("config must be an object")
        out = {}
        for key, value in given.items():
            if key == "permissions":
                continue
            spec = fields.get(key)
            if spec is None:
                if before is not None and key in before and before[key] == value:
                    out[key] = value   # carried over from an import, untouched
                    continue
                raise Invalid(f"unknown setting: {key}")
            if value is None or value == "" or (spec["type"] == LIST and value == [] and key != "include_extensions"):
                continue   # unset: the type's global default applies
            t = spec["type"]
            if t == TEXT:
                if not isinstance(value, str):
                    raise Invalid(f"{key} must be text")
                value = value.strip()
                if not value or len(value) > 1000:
                    continue
            elif t == BOOL:
                if not isinstance(value, bool):
                    raise Invalid(f"{key} must be true or false")
            elif t == LIST:
                value = _clean_list(value, key)
            elif t == DATE:
                if not isinstance(value, str) or not DATE_RE.match(value):
                    raise Invalid(f"{key} must be a date, YYYY-MM-DD")
            elif t == CHOICE:
                if value not in spec["choices"]:
                    raise Invalid(f"{key} must be one of {', '.join(spec['choices'])}")
            out[key] = value
        if kind == "sharepoint" and given.get("include_extensions") == []:
            out["include_extensions"] = []   # explicit: this site uses the exclude lists
        for key, spec in fields.items():
            if spec.get("required") and not out.get(key):
                raise Invalid(f"{key} is required")
        if kind == "smb":
            if not HOST_RE.match(out["server"]):
                raise Invalid("server must be a host name or IP address")
            out.setdefault("path", "")
        if kind == "sharepoint" and not re.match(r"^https://[^/\s]+/\S*$", out["url"]):
            raise Invalid("url must be the site's full https:// address")

        def same(key):   # unset and empty count as the same
            return (out.get(key) in (None, "")) and ((before or {}).get(key) in (None, "")) \
                or out.get(key) == (before or {}).get(key)
        if before is not None:
            for key, spec in fields.items():
                if spec.get("fixed") and not same(key):
                    raise Invalid(f"{key} can't be changed after a source is created; add a new source "
                                  "and remove this one instead")
        for key, spec in fields.items():
            if spec.get("super_admin") and not user.super_admin and not same(key):
                raise Invalid(f"only a super admin can set {key}, since it changes who can see the documents")
        if HAS_PERMISSIONS[kind]:
            perms = given.get("permissions") or {}
            if not isinstance(perms, dict):
                raise Invalid("permissions must be an object")
            clean = {}
            for gk in GRANT_KINDS:
                values = _clean_list(perms.get(gk), f"permissions.{gk}")
                if gk == "users":
                    values = [v.lower() for v in values]
                if values:
                    clean[gk] = values
            if clean:
                out["permissions"] = clean
        return out

    def _check_scope_limits(self, user: User, kind: str, scope: dict | None, config: dict,
                            credential: str | None, before: dict | None, minutes: list[int]) -> None:
        """What a scoped admin may set. Super admins aren't limited."""
        if user.super_admin:
            return
        if scope is None:
            raise Forbidden()
        if kind not in scope["kinds"]:
            raise Invalid(f"this scope can't hold {KIND_INFO[kind]['label']} sources")
        if kind == "smb" and config["server"].lower() not in scope["smb_servers"]:
            raise Invalid(f"this scope can't crawl server {config['server']}; a super admin can add it to the scope")
        if kind == "smb" and (credential or DEFAULT_CREDENTIALS) not in scope["credentials"]:
            raise Invalid("this scope can't use that credential profile")
        if HAS_PERMISSIONS[kind]:
            allowed = {"users": set(scope["grant_users"]), "groups": {g.lower() for g in scope["grant_groups"]},
                       "roles": {r.lower() for r in scope["grant_roles"]}}
            old = (before or {}).get("permissions") or {}
            for gk in GRANT_KINDS:
                old_values = {v.lower() for v in old.get(gk, [])}
                for v in (config.get("permissions") or {}).get(gk, []):
                    # A grant a super admin already made may stay; new ones must be allowed.
                    if v.lower() not in allowed[gk] and v.lower() not in old_values:
                        raise Invalid(f"this scope can't grant access to {gk[:-1]} '{v}'")
        for m in minutes:
            if m and m < scope["min_minutes"]:
                raise Invalid(f"this scope's shortest schedule is every {scope['min_minutes']} minutes")

    def _minutes(self, body: dict, key: str, default: int) -> int:
        value = body.get(key, default)
        try:
            value = int(value or 0)
        except (TypeError, ValueError):
            raise Invalid("a schedule must be a whole number of minutes (0 for manual only)")
        if value and value < MIN_INTERVAL_MINUTES:
            raise Invalid(f"the shortest schedule is every {MIN_INTERVAL_MINUTES} minutes")
        if value > 60 * 24 * 90:
            raise Invalid("the longest schedule is every 90 days")
        return value

    def save_source(self, user: User, body: dict, source_id=None) -> dict:
        with self.lock:
            before = self.managed_source(user, source_id) if source_id is not None else None
            kind = before["kind"] if before else body.get("kind")
            if kind not in KINDS:
                raise Invalid("choose a source type")
            if before:
                name = before["name"]
                if body.get("name") not in (None, name):
                    raise Invalid("a source can't be renamed: its name is on every document it indexed")
                if before["removing"]:
                    raise Invalid("this source is being removed")
            else:
                name = str(body.get("name") or "").strip()
                if not NAME_RE.match(name):
                    raise Invalid("a name is 1-64 letters, digits, '.', '_' or '-', starting with a letter or digit")
                if self._one("SELECT 1 FROM sources WHERE name = ? COLLATE NOCASE", (name,)):
                    raise Invalid("a source with that name already exists (names are shared by all source types)")

            scope_id = body.get("scope_id", before["scope_id"] if before else None)
            scope_id = int(scope_id) if scope_id not in (None, "") else None
            if before and scope_id != before["scope_id"] and not user.super_admin:
                raise Invalid("only a super admin can move a source to another scope")
            if not user.super_admin and scope_id not in self._managed_scope_ids(user):
                raise Invalid("choose one of your scopes")
            scope = self.scope(scope_id) if scope_id is not None else None

            config = self._validate_fields(kind, body.get("config") or {}, before["config"] if before else None, user)
            credential = None
            if kind == "smb":
                credential = str(body.get("credential") or "").strip() or None
                if credential == DEFAULT_CREDENTIALS:
                    credential = None
                if credential and not self.credential(credential):
                    raise Invalid("no such credential profile")
            crawl = self._minutes(body, "crawl_minutes", before["crawl_minutes"] if before else self.defaults["crawl_minutes"])
            acl = self._minutes(body, "acl_minutes", before["acl_minutes"] if before else self.defaults["acl_minutes"]) \
                if kind == "smb" else 0
            enabled = bool(body.get("enabled", before["enabled"] if before else True))
            self._check_scope_limits(user, kind, scope, config, credential, before["config"] if before else None,
                                     [crawl, acl])

            now = time.time()
            if before is None:
                position = (self._one("SELECT MAX(position) AS p FROM sources")["p"] or 0) + 1
                cur = self.db.execute(
                    "INSERT INTO sources (kind, name, scope_id, enabled, config, credential, crawl_minutes, acl_minutes,"
                    " position, created_at, created_by, updated_at, updated_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (kind, name, scope_id, int(enabled), json.dumps(config), credential, crawl, acl, position,
                     now, user.username, now, user.username))
                source_id = cur.lastrowid
                self.audit(user.username, "source added", name, scope_id,
                           {"kind": kind, "config": config, "credential": credential,
                            "crawl_minutes": crawl, "acl_minutes": acl, "enabled": enabled})
            else:
                self.db.execute(
                    "UPDATE sources SET scope_id=?, enabled=?, config=?, credential=?, crawl_minutes=?, acl_minutes=?,"
                    " updated_at=?, updated_by=? WHERE id=?",
                    (scope_id, int(enabled), json.dumps(config), credential, crawl, acl, now, user.username, source_id))
                after = {"scope_id": scope_id, "enabled": enabled, "config": config, "credential": credential,
                         "crawl_minutes": crawl, "acl_minutes": acl}
                changes = {k: {"before": before[k], "after": v} for k, v in after.items() if before[k] != v}
                if changes:
                    self.audit(user.username, "source changed", name, scope_id, changes)
                if before["enabled"] and not enabled:
                    # Disabling stops what's waiting; a running crawl finishes.
                    self.db.execute("UPDATE jobs SET status='cancelled', finished_at=? WHERE source_id=?"
                                    " AND status='queued' AND type IN ('crawl','acl')", (now, source_id))
            self.db.commit()
        self.on_change()
        return self.source(source_id)

    def remove_source(self, user: User, source_id, confirm: str) -> dict:
        """Marks the source for removal and queues the purge that deletes
        its documents and crawl state; the row goes once that succeeds."""
        with self.lock:
            source = self.managed_source(user, source_id)
            if confirm != source["name"]:
                raise Invalid("type the source's name to confirm")
            if source["removing"]:
                raise Invalid("this source is already being removed")
            now = time.time()
            self.db.execute("UPDATE sources SET removing=1, enabled=0, updated_at=?, updated_by=? WHERE id=?",
                            (now, user.username, source_id))
            self.db.execute("UPDATE jobs SET status='cancelled', finished_at=? WHERE source_id=? AND status='queued'",
                            (now, source_id))
            self.db.execute("UPDATE jobs SET cancel=1 WHERE source_id=? AND status='running'", (source_id,))
            self._insert_job(source_id, "purge", user.username, now)
            self.audit(user.username, "source removal started", source["name"], source["scope_id"],
                       {"kind": source["kind"], "config": source["config"]})
            self.db.commit()
            return self.source(source_id)

    # ----------------------------------------------------------- jobs

    def _insert_job(self, source_id, job_type, requested_by, now):
        cur = self.db.execute(
            "INSERT INTO jobs (source_id, type, status, requested_by, created_at) VALUES (?, ?, 'queued', ?, ?)",
            (source_id, job_type, requested_by, now))
        return cur.lastrowid

    def _job_row(self, row) -> dict:
        return {k: row[k] for k in row.keys()}

    def jobs_for(self, source_id, limit=20) -> list[dict]:
        return [self._job_row(r) for r in self._q(
            "SELECT * FROM jobs WHERE source_id = ? ORDER BY id DESC LIMIT ?", (source_id, limit))]

    def last_jobs(self) -> dict:
        """Per source: the latest job of each type, for the sources list."""
        out: dict = {}
        rows = self._q("SELECT j.* FROM jobs j JOIN (SELECT source_id, type, MAX(id) AS id FROM jobs"
                       " GROUP BY source_id, type) m ON j.id = m.id")
        for r in rows:
            out.setdefault(r["source_id"], {})[r["type"]] = {
                k: r[k] for k in ("id", "status", "created_at", "started_at", "finished_at", "summary", "worker")}
        # Also the last finished crawl, so a queued or running one doesn't hide it.
        rows = self._q("SELECT j.* FROM jobs j JOIN (SELECT source_id, MAX(id) AS id FROM jobs"
                       " WHERE type = 'crawl' AND status IN ('done','failed') GROUP BY source_id) m ON j.id = m.id")
        for r in rows:
            out.setdefault(r["source_id"], {})["last_crawl"] = {
                k: r[k] for k in ("id", "status", "finished_at", "summary")}
        return out

    def job(self, job_id) -> dict:
        row = self._one("SELECT * FROM jobs WHERE id = ?", (job_id,))
        if not row:
            raise NotFound("no such job")
        return self._job_row(row)

    def request_job(self, user: User, source_id, job_type: str) -> dict:
        with self.lock:
            source = self.managed_source(user, source_id)
            if job_type not in ("crawl", "acl", "test"):
                raise Invalid("unknown job")
            if job_type == "acl" and source["kind"] != "smb":
                raise Invalid("only SMB shares have an ACL sync")
            if source["removing"]:
                raise Invalid("this source is being removed")
            if job_type != "test" and not source["enabled"]:
                raise Invalid("this source is disabled; enable it first")
            if self._one("SELECT 1 FROM jobs WHERE source_id=? AND type=? AND status IN ('queued','running')",
                         (source_id, job_type)):
                raise Invalid("that job is already queued or running")
            job_id = self._insert_job(source_id, job_type, user.username, time.time())
            self.audit(user.username, f"{job_type} requested", source["name"], source["scope_id"])
            self.db.commit()
            return self.job(job_id)

    def cancel_job(self, user: User, job_id) -> dict:
        with self.lock:
            job = self.job(job_id)
            source = self.managed_source(user, job["source_id"])
            if job["type"] == "purge":
                raise Invalid("a removal can't be cancelled")
            if job["status"] == "queued":
                self.db.execute("UPDATE jobs SET status='cancelled', finished_at=? WHERE id=?", (time.time(), job_id))
            elif job["status"] == "running":
                self.db.execute("UPDATE jobs SET cancel=1 WHERE id=?", (job_id,))
            else:
                raise Invalid("that job has finished")
            self.audit(user.username, f"{job['type']} cancelled", source["name"], source["scope_id"])
            self.db.commit()
            return self.job(job_id)

    def _enqueue_due(self, now: float) -> None:
        """Queue each enabled source's crawl (and SMB ACL sync) once its
        interval has passed since the last one was queued."""
        for s in self.all_sources():
            if not s["enabled"] or s["removing"]:
                continue
            for job_type, minutes in (("crawl", s["crawl_minutes"]), ("acl", s["acl_minutes"])):
                if not minutes or (job_type == "acl" and s["kind"] != "smb"):
                    continue
                if self._one("SELECT 1 FROM jobs WHERE source_id=? AND type=? AND status IN ('queued','running')",
                             (s["id"], job_type)):
                    continue
                last = self._one("SELECT MAX(created_at) AS t FROM jobs WHERE source_id=? AND type=?"
                                 " AND status != 'cancelled'", (s["id"], job_type))["t"]
                if last is None or last + minutes * 60 <= now:
                    self._insert_job(s["id"], job_type, "schedule", now)

    def _expire_leases(self, now: float) -> None:
        for table in ("jobs", "index_jobs"):
            for r in self._q(f"SELECT id, worker FROM {table} WHERE status='running' AND lease_until < ?", (now,)):
                self.db.execute(f"UPDATE {table} SET status='failed', finished_at=?, summary=? WHERE id=?",
                                (now, f"worker {r['worker']} stopped responding", r["id"]))

    def claim(self, worker: str, running: int, version: str = "", now: float | None = None) -> dict | None:
        """Hands the next due job to a worker, or None. A worker runs at most
        worker_slots(worker) jobs at once. Index jobs go first; a purge waits
        until nothing else runs for its source; then test and purge jobs.
        While a rebuild or switch is queued or running, no crawl, ACL sync or
        removal starts (tests still do)."""
        now = now or time.time()
        with self.lock:
            slots = self.worker_slots(worker)
            self._touch_worker(worker, slots, running, version, now)
            self._expire_leases(now)
            self._enqueue_due(now)
            job = None
            if running < slots:
                job = self._claim_index_job(worker, now)
            holding = self.holding()
            if running < slots and job is None:
                # created_at in the future: a retry that isn't due yet.
                rows = self._q("SELECT * FROM jobs WHERE status='queued' AND created_at <= ? ORDER BY"
                               " CASE type WHEN 'test' THEN 0 WHEN 'purge' THEN 1 ELSE 2 END, created_at, id", (now,))
                for r in rows:
                    if holding and r["type"] != "test":
                        continue
                    source = self.source(r["source_id"])
                    busy = self._one("SELECT 1 FROM jobs WHERE source_id=? AND status='running'"
                                     + ("" if r["type"] == "purge" else " AND type=?"),
                                     (r["source_id"],) if r["type"] == "purge" else (r["source_id"], r["type"]))
                    if busy:
                        continue
                    self.db.execute("UPDATE jobs SET status='running', worker=?, started_at=?, lease_until=? WHERE id=?",
                                    (worker, now, now + LEASE_SECONDS, r["id"]))
                    job = {"id": r["id"], "type": r["type"], "source": {"kind": source["kind"], "name": source["name"]},
                           "config_env": KIND_INFO[source["kind"]]["config_env"],
                           "names_env": KIND_INFO[source["kind"]]["names_env"],
                           "config_yaml": self.render(source["kind"], [source])}
                    break
            self.db.commit()
            return job

    def _touch_worker(self, worker, slots, running, version, now):
        self.db.execute("INSERT OR REPLACE INTO workers (name, last_seen, slots, running, version) VALUES (?,?,?,?,?)",
                        (worker, now, slots, running, version))

    def _owned_job(self, worker: str, job_id) -> dict:
        job = self.job(job_id)
        if job["status"] != "running" or job["worker"] != worker:
            raise Invalid("this job is no longer yours")
        return job

    def heartbeat(self, worker: str, job_id, log: str = "", now: float | None = None,
                  progress: str = "") -> dict:
        """Keeps the job's lease, and stores its output so far and running
        totals (shown as its result until it finishes)."""
        now = now or time.time()
        with self.lock:
            job = self._owned_job(worker, job_id)
            self.db.execute("UPDATE jobs SET lease_until=?, log=?, summary=COALESCE(?, summary) WHERE id=?",
                            (now + LEASE_SECONDS, (log or "")[-JOB_LOG_CHARS:], (progress or None) and progress[:500],
                             job_id))
            self.db.execute("UPDATE workers SET last_seen=? WHERE name=?", (now, worker))
            self.db.commit()
            return {"cancel": bool(job["cancel"])}

    def finish(self, worker: str, job_id, ok: bool, exit_code=None, log: str = "", summary: str = "",
               now: float | None = None) -> None:
        now = now or time.time()
        with self.lock:
            job = self._owned_job(worker, job_id)
            status = "done" if ok else ("cancelled" if job["cancel"] and job["type"] != "purge" else "failed")
            self.db.execute("UPDATE jobs SET status=?, finished_at=?, exit_code=?, log=?, summary=? WHERE id=?",
                            (status, now, exit_code, (log or "")[-JOB_LOG_CHARS:], (summary or "")[:500], job_id))
            source = self.source(job["source_id"])
            if job["type"] == "purge" and ok:
                self.db.execute("DELETE FROM jobs WHERE source_id=?", (source["id"],))
                self.db.execute("DELETE FROM sources WHERE id=?", (source["id"],))
                self.audit("worker:" + worker, "source removed", source["name"], source["scope_id"],
                           {"summary": summary})
            elif job["type"] == "purge":
                # Try again in a few minutes; the source stays marked for removal.
                self._insert_job(source["id"], "purge", "retry", now + PURGE_RETRY_SECONDS)
            else:
                self.db.execute(
                    "DELETE FROM jobs WHERE source_id=? AND id NOT IN (SELECT id FROM jobs WHERE source_id=?"
                    " ORDER BY id DESC LIMIT ?)", (source["id"], source["id"], JOBS_KEPT_PER_SOURCE))
            self.db.commit()
        if job["type"] == "purge" and ok:
            self.on_change()

    # ------------------------------------------------------- index jobs

    def vector_settings(self) -> dict:
        """What the next rebuild uses: saved on the Index page, else the defaults."""
        saved = self.meta("vector_settings")
        return {**self.vector_defaults, **(json.loads(saved) if saved else {})}

    def save_vector_settings(self, user: User, body: dict) -> dict:
        if not user.super_admin:
            raise Forbidden()
        out = dict(self.vector_settings())
        if "enabled" in body:
            out["enabled"] = bool(body["enabled"])
        url = str(body.get("embeddings_url", out["embeddings_url"])).strip()
        if not URL_RE.match(url):
            raise Invalid("the embeddings server must be an http:// or https:// address, "
                          "e.g. http://embeddings/embed")
        model = str(body.get("model", out["model"])).strip()
        if not model or len(model) > 200 or any(c.isspace() for c in model):
            raise Invalid("name the model the embeddings server runs, e.g. BAAI/bge-base-en-v1.5")

        def number(key, cast, low, high, what):
            try:
                value = cast(body.get(key, out[key]))
            except (TypeError, ValueError):
                raise Invalid(f"{what} must be a number")
            if not low <= value <= high:
                raise Invalid(f"{what} must be between {low} and {high}")
            return value
        out.update({
            "embeddings_url": url, "model": model,
            "chunk_words": number("chunk_words", int, 50, 2000, "passage size"),
            "chunk_overlap": number("chunk_overlap", float, 0, 0.5, "overlap"),
            "max_chunks": number("max_chunks", int, 1, 1000, "passages per document"),
        })
        with self.lock:
            before = self.vector_settings()
            self.set_meta("vector_settings", json.dumps(out))
            if before != out:
                self.audit(user.username, "vector settings changed", "index", None, {"before": before, "after": out})
            self.db.commit()
        return out

    def _index_job_row(self, row) -> dict:
        job = {k: row[k] for k in row.keys()}
        job["op"] = json.loads(job["op"])
        return job

    def index_jobs(self, limit=20) -> list[dict]:
        return [self._index_job_row(r) for r in self._q("SELECT * FROM index_jobs ORDER BY id DESC LIMIT ?", (limit,))]

    def index_job(self, job_id) -> dict:
        row = self._one("SELECT * FROM index_jobs WHERE id = ?", (job_id,))
        if not row:
            raise NotFound("no such index job")
        return self._index_job_row(row)

    def holding(self) -> bool:
        """Whether a rebuild or switch is queued or running, holding crawls."""
        marks = ",".join("?" * len(HOLDING_ACTIONS))
        return bool(self._one(f"SELECT 1 FROM index_jobs WHERE status IN ('queued','running')"
                              f" AND action IN ({marks})", HOLDING_ACTIONS))

    def writes_since(self, since: float) -> list[dict]:
        """Crawls, ACL syncs and removals that started after `since`: they wrote
        to the live index, which switching back would lose."""
        return [self._job_row(r) for r in self._q(
            "SELECT * FROM jobs WHERE type IN ('crawl','acl','purge') AND started_at >= ?", (since,))]

    def request_index_job(self, user: User, action: str) -> dict:
        """Queue an index job. The caller checks against the live index that
        it makes sense (e.g. that there's a previous index to switch to)."""
        if not user.super_admin:
            raise Forbidden()
        if action not in INDEX_ACTIONS:
            raise Invalid("unknown index job")
        with self.lock:
            if self._one("SELECT 1 FROM index_jobs WHERE status IN ('queued','running')"):
                raise Invalid("another index job is queued or running; wait for it to finish")
            vs = self.vector_settings()
            op = {"action": action, "requested_by": user.username}
            if action == "check":
                op["vectors"] = {k: vs[k] for k in VECTOR_DEFAULTS if k != "enabled"}
            elif action == "rebuild":
                op["vectors"] = {k: vs[k] for k in VECTOR_DEFAULTS if k != "enabled"} if vs["enabled"] else None
            cur = self.db.execute(
                "INSERT INTO index_jobs (action, op, status, requested_by, created_at) VALUES (?, ?, 'queued', ?, ?)",
                (action, json.dumps(op), user.username, time.time()))
            self.audit(user.username, f"index {action.replace('_', ' ')} requested", "index", None,
                       {"vectors": op.get("vectors")} if "vectors" in op else None)
            self.db.commit()
            return self.index_job(cur.lastrowid)

    def cancel_index_job(self, user: User, job_id) -> dict:
        if not user.super_admin:
            raise Forbidden()
        with self.lock:
            job = self.index_job(job_id)
            if job["status"] == "queued":
                self.db.execute("UPDATE index_jobs SET status='cancelled', finished_at=? WHERE id=?",
                                (time.time(), job_id))
            elif job["status"] == "running":
                self.db.execute("UPDATE index_jobs SET cancel=1 WHERE id=?", (job_id,))
            else:
                raise Invalid("that job has finished")
            self.audit(user.username, f"index {job['action'].replace('_', ' ')} cancelled", "index")
            self.db.commit()
            return self.index_job(job_id)

    def _claim_index_job(self, worker: str, now: float) -> dict | None:
        row = self._one("SELECT * FROM index_jobs WHERE status='queued' ORDER BY id LIMIT 1")
        if not row:
            return None
        if row["action"] in HOLDING_ACTIONS and self._one(
                "SELECT 1 FROM jobs WHERE status='running' AND type IN ('crawl','acl','purge')"):
            return None   # waits for running crawls to finish
        self.db.execute("UPDATE index_jobs SET status='running', worker=?, started_at=?, lease_until=? WHERE id=?",
                        (worker, now, now + LEASE_SECONDS, row["id"]))
        return {"id": row["id"], "type": "index", "op": json.loads(row["op"])}

    def _owned_index_job(self, worker: str, job_id) -> dict:
        job = self.index_job(job_id)
        if job["status"] != "running" or job["worker"] != worker:
            raise Invalid("this job is no longer yours")
        return job

    def index_heartbeat(self, worker: str, job_id, log: str = "", now: float | None = None,
                        progress: str = "") -> dict:
        now = now or time.time()
        with self.lock:
            job = self._owned_index_job(worker, job_id)
            self.db.execute("UPDATE index_jobs SET lease_until=?, log=?, summary=COALESCE(?, summary) WHERE id=?",
                            (now + LEASE_SECONDS, (log or "")[-JOB_LOG_CHARS:], (progress or None) and progress[:500],
                             job_id))
            self.db.execute("UPDATE workers SET last_seen=? WHERE name=?", (now, worker))
            self.db.commit()
            return {"cancel": bool(job["cancel"])}

    def index_finish(self, worker: str, job_id, ok: bool, exit_code=None, log: str = "", summary: str = "",
                     now: float | None = None) -> None:
        now = now or time.time()
        with self.lock:
            job = self._owned_index_job(worker, job_id)
            status = "done" if ok else ("cancelled" if job["cancel"] else "failed")
            self.db.execute("UPDATE index_jobs SET status=?, finished_at=?, exit_code=?, log=?, summary=? WHERE id=?",
                            (status, now, exit_code, (log or "")[-JOB_LOG_CHARS:], (summary or "")[:500], job_id))
            self.audit("worker:" + worker, f"index {job['action'].replace('_', ' ')} {status}", "index", None,
                       {"summary": summary})
            self.db.execute("DELETE FROM index_jobs WHERE id NOT IN (SELECT id FROM index_jobs ORDER BY id DESC"
                            " LIMIT ?)", (INDEX_JOBS_KEPT,))
            self.db.commit()

    # ---------------------------------------------------- worker settings

    def default_worker_slots(self) -> int:
        return int(self.meta("worker_slots", DEFAULT_WORKER_SLOTS))

    def worker_slots(self, worker: str) -> int:
        """How many jobs this worker runs at once: its own setting, else the default."""
        row = self._one("SELECT slots FROM worker_settings WHERE name = ?", (worker,))
        return row["slots"] if row else self.default_worker_slots()

    def _valid_slots(self, slots) -> int:
        try:
            slots = int(slots)
        except (TypeError, ValueError):
            raise Invalid("jobs at once must be a whole number")
        if not 1 <= slots <= MAX_WORKER_SLOTS:
            raise Invalid(f"jobs at once must be between 1 and {MAX_WORKER_SLOTS}")
        return slots

    def set_default_worker_slots(self, user: User, slots) -> int:
        if not user.super_admin:
            raise Forbidden()
        slots = self._valid_slots(slots)
        with self.lock:
            before = self.default_worker_slots()
            self.set_meta("worker_slots", str(slots))
            self.audit(user.username, "worker default changed", "jobs at once", None,
                       {"before": before, "after": slots})
            self.db.commit()
        return slots

    def set_worker_slots(self, user: User, worker: str, slots) -> int:
        """One worker's own setting; None goes back to the default."""
        if not user.super_admin:
            raise Forbidden()
        if not worker or len(worker) > 100:
            raise Invalid("no such worker")
        with self.lock:
            before = self.worker_slots(worker)
            if slots is None:
                self.db.execute("DELETE FROM worker_settings WHERE name = ?", (worker,))
            else:
                self.db.execute("INSERT OR REPLACE INTO worker_settings (name, slots) VALUES (?, ?)",
                                (worker, self._valid_slots(slots)))
            after = self.worker_slots(worker)
            self.audit(user.username, "worker changed", worker, None,
                       {"jobs at once": {"before": before, "after": "default" if slots is None else after}})
            self.db.commit()
            return after

    def workers(self, now: float | None = None) -> list[dict]:
        """Workers heard from in the last hour. One that stopped more recently
        still shows, so the page can say it isn't responding."""
        now = now or time.time()
        with self.lock:
            self.db.execute("DELETE FROM workers WHERE last_seen < ?", (now - WORKER_FORGET_SECONDS,))
            self.db.commit()
            default = self.default_worker_slots()
            own = {r["name"]: r["slots"] for r in self._q("SELECT * FROM worker_settings")}
            out = []
            for r in self._q("SELECT * FROM workers ORDER BY name"):
                w = dict(r)
                w["slots"] = own.get(w["name"], default)
                w["own_slots"] = w["name"] in own
                out.append(w)
            return out

    def audit_entries(self, user: User, limit=200, before_id=None) -> list[dict]:
        sql = "SELECT * FROM audit"
        args: list = []
        where = []
        if not user.super_admin:
            ids = sorted(self._managed_scope_ids(user))
            where.append(f"scope_id IN ({','.join('?' * len(ids)) or 'NULL'})")
            args += ids
        if before_id:
            where.append("id < ?")
            args.append(int(before_id))
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(int(limit))
        out = []
        for r in self._q(sql, args):
            e = dict(r)
            e["detail"] = json.loads(e["detail"]) if e["detail"] else None
            out.append(e)
        return out

    # -------------------------------------------------------- rendering

    def _entry(self, source: dict) -> dict:
        entry = {"name": source["name"]}
        entry.update(copy.deepcopy(source["config"]))
        if source["kind"] == "smb" and source["credential"]:
            cred = self.credential(source["credential"]) or {}
            for f in CREDENTIAL_FIELDS:
                if cred.get(f):
                    entry[f] = cred[f]
        return entry

    def render(self, kind: str, sources: list[dict]) -> str:
        """The YAML file the crawler for `kind` reads, holding `sources`."""
        data = copy.deepcopy(self.settings(kind))
        data[KIND_INFO[kind]["list_key"]] = [self._entry(s) for s in sources]
        header = ("# Written by the Pelican admin portal; changes made here are overwritten.\n"
                  "# Edit sources and settings in the portal instead.\n")
        return header + _dump_yaml(data)

    def render_all(self) -> dict[str, str]:
        """Every type's file with every source still in the index (including
        disabled ones and ones being removed), for Frogmouth's downloads and
        the mailbox permission export."""
        return {KIND_INFO[k]["file"]: self.render(k, self.all_sources(k)) for k in KINDS}

    # ----------------------------------------------------------- import

    def import_yaml(self, kind: str, text: str, by: str = "import") -> int:
        """Adds the sources and settings from an existing YAML file, once,
        on first start. Sources get no scope (super admins only) and the
        default schedule. Returns how many sources were added."""
        data = yaml.safe_load(text) or {}
        if not isinstance(data, dict):
            raise Invalid(f"{KIND_INFO[kind]['file']} isn't a YAML mapping")
        list_key = KIND_INFO[kind]["list_key"]
        entries = data.pop(list_key, None) or []
        added = 0
        with self.lock:
            if not self._one("SELECT 1 FROM settings WHERE kind = ?", (kind,)):
                self.db.execute("INSERT INTO settings (kind, data) VALUES (?, ?)", (kind, json.dumps(data)))
            for entry in entries:
                if not isinstance(entry, dict) or not entry.get("name"):
                    continue
                entry = dict(entry)
                name = str(entry.pop("name"))
                if "," in name or self._one("SELECT 1 FROM sources WHERE name = ? COLLATE NOCASE", (name,)):
                    print(f"import: skipped {kind} source {name!r} (a comma in its name, or the name is taken)")
                    continue
                credential = None
                if kind == "smb" and any(entry.get(f) for f in CREDENTIAL_FIELDS):
                    fields = {f: str(entry.pop(f, "") or "") for f in CREDENTIAL_FIELDS}
                    credential = self._import_credential(fields)
                now = time.time()
                position = (self._one("SELECT MAX(position) AS p FROM sources")["p"] or 0) + 1
                self.db.execute(
                    "INSERT INTO sources (kind, name, scope_id, enabled, config, credential, crawl_minutes, acl_minutes,"
                    " position, created_at, created_by, updated_at, updated_by) VALUES (?,?,NULL,1,?,?,?,?,?,?,?,?,?)",
                    (kind, name, json.dumps(entry), credential, self.defaults["crawl_minutes"],
                     self.defaults["acl_minutes"] if kind == "smb" else 0, position, now, by, now, by))
                added += 1
            self.audit(by, "imported", KIND_INFO[kind]["file"], None, {"sources": added})
            self.db.commit()
        self.on_change()
        return added

    def _import_credential(self, fields: dict) -> str:
        for c in self.credentials():
            if all(c.get(f, "") == fields[f] for f in CREDENTIAL_FIELDS):
                return c["name"]
        base = re.sub(r"[^A-Za-z0-9_.-]", "", fields["user_env"].lower()) or "imported"
        name, n = base, 2
        while self.credential(name) or name == DEFAULT_CREDENTIALS:
            name, n = f"{base}-{n}", n + 1
        self.db.execute("INSERT INTO credentials (name, kind, data) VALUES (?, 'smb', ?)",
                        (name, json.dumps({**fields, "note": "imported from shares.yaml"})))
        return name
