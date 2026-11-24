# Pelican

Permission-aware crawlers that feed an OpenSearch index from **SMB file
shares**, **Exchange Online mailboxes** and **SharePoint Online sites**.

Each document carries access roles taken from its source's own permissions
(SMB folder ACLs, mailbox Full Access, Microsoft 365 group membership), so a
search front end can show every user only what they're allowed to see. All
crawlers write one shared schema into one index; Frogmouth is a companion
search UI built for it.

## Features

- **SMB** 2.0.2 to 3.1.1 via smbprotocol (no host mounts), with Windows file
  servers, Samba and NAS devices: parallel fetch, incremental by
  modification time, deletion detection with guards against wiping a share
  on a bad listing, and per-folder ACLs via `smbcacls` with a separate job that
  re-applies permission changes without re-downloading anything. Traffic is
  signed; set `encrypt: true` on a share to require SMB3 encryption.
- **Exchange Online** via Microsoft Graph delta queries: full MIME per message,
  attachment text, Full Access holders mapped to AD accounts.
- **SharePoint Online** via Graph with `Sites.Selected` (only the sites you
  grant): delta queries per library, extension whitelist, site group members
  mirrored as access.
- **Text extraction** for PDF (isolated, with a timeout), Word (DOCX, DOC),
  presentations (PPTX, PPT, ODP, including speaker notes), ODT, RTF, EML/MSG
  and plain text; attachment names for email, and EXIF camera and GPS data
  for images, reverse-geocoded offline. Files indexed before a format was
  supported get its text on the next crawl. Spreadsheets are indexed by
  filename only.
- **Optional vector search**: passages embedded in OpenSearch's ingest
  pipeline, on a CPU or NVIDIA GPU, for search by meaning (see
  [Vector search](#vector-search)). Off by default.
- **Fail-closed access**: if permissions can't be read, new content is
  restricted and existing content keeps its last known access.
- **Built for unattended runs**: one-shot jobs, a process watchdog for silent
  network hangs, and an [admin portal](#admin-portal) showing every job and
  index growth.

## Quick start

Requires Docker with Compose.

```sh
cp .env.example .env                      # credentials, OpenSearch passwords
$EDITOR config/shares.yaml                # and/or exchange.yaml, sharepoint.yaml
docker compose -f docker-compose.example.yml up -d
```

This pulls the published images from `ghcr.io/silcrats` (`pelican`,
`pelican-exo-permissions`, and `pelican-admin` for the portal). Set `PELICAN_VERSION` in `.env`
to pin a release, or add `--build` to build from your checkout instead.

The example runs a single-node OpenSearch with its security plugin on (see
[OpenSearch security](#opensearch-security)), one container per job
scheduled by [ofelia](https://github.com/mcuadros/ofelia). Remove the
services you don't need. To see jobs and storage in a browser, add the
[admin portal](#admin-portal).

Each crawler is a one-shot process: it crawls once and exits. If any share,
mailbox or site fails, it still crawls the rest, then exits with status 1
and lists the failures (its log shows why). The image defaults to
`crawl_smb.py`; choose another job with an entrypoint override.

With the [admin portal](#admin-portal), workers run these jobs on each
source's schedule instead, and the sources live in the portal.

| Job | Purpose | Config |
| --- | --- | --- |
| `crawl_smb.py` | SMB shares → index | `config/shares.yaml` |
| `sync_smb_acl.py` | Re-check SMB folder ACLs, update roles on indexed docs | `config/shares.yaml` |
| `crawl_exchange.py` | Exchange Online mailboxes → index | `config/exchange.yaml` |
| `crawl_sharepoint.py` | SharePoint Online sites → index | `config/sharepoint.yaml` |
| `exo-permissions/` | Export mailbox Full Access holders (PowerShell) | `config/exchange.yaml` |

The comments at the top of each config file cover the Entra ID / Exchange /
SharePoint permissions each job needs. Every Graph permission is read-only.

## Configuration

`config/pelican.yaml` holds the shared settings: the index, how access roles
are encoded, and the `host` value each crawler writes. The per-source files
say what to crawl. All four are baked into the image; mount over
`/app/config` (or set the env vars below) to change them without a rebuild.
Any YAML string may use `${VAR}` or `${VAR:-fallback}`.

Credentials never go in the YAML. Each config names the environment variables
that hold them (`user_env` / `pass_env` / `domain_env` for SMB,
`tenant_id_env` / `client_id_env` / `secret_env` for Graph).

| Env var | Default | Purpose |
| --- | --- | --- |
| `PELICAN_CONFIG` | `/app/config/pelican.yaml` | Core settings |
| `SHARES_CONFIG`, `EXCHANGE_CONFIG`, `SHAREPOINT_CONFIG` | `/app/config/<name>.yaml` | Per-source config |
| `OS_HOST`, `SEARCH_INDEX` | `http://opensearch:9200`, `documents` | OpenSearch target |
| `OS_USERNAME`, `OS_PASSWORD` | none | OpenSearch sign-in, for a cluster with the security plugin |
| `OS_CA_CERTS` | system CAs | CA certificate file that signed OpenSearch's certificate |
| `STATE_DB_PATH` | `/state/pelican_state.db` | Incremental state. One volume per crawler; an SMB crawler and its ACL sync share one |
| `JOB_NAME`, `STATUS_DIR` | `primary`, `/status` | Progress file name and location (the portal's worker reads it for running totals) |
| `SHARE_NAMES`, `MAILBOX_NAMES`, `SITE_NAMES` | all | Comma-separated subset for this container, to split work across containers |
| `TZ` | UTC | Time zone for status timestamps |

Tuning (all optional): `BATCH_SIZE`, `SMB_WORKERS`, `GRAPH_WORKERS`,
`SP_WORKERS`, `ACL_SYNC_WORKERS`, `ACL_RECHECK_HOURS`, `PDF_TIMEOUT_SECONDS`,
`WATCHDOG_TIMEOUT_SECONDS`, `SMB_CONNECT_TIMEOUT_SECONDS`,
`SMB_LIST_TIMEOUT_SECONDS`, `SMB_FETCH_TIMEOUT_SECONDS`,
`SMB_LIST_STALL_SECONDS`, `GRAPH_MAX_RETRIES`, `MAX_CONTENT_CHARS` (text
kept per document, default 10 million characters; OpenSearch refuses more
than 50 million), `BULK_MAX_MB` (largest bulk request, default 10).
`OS_HEAP` sets the compose example's OpenSearch heap (default `2g`).

All three images run as UID 10001, not root. Anything you mount (config,
`secrets/exo.pfx`, the state, status and permissions volumes) must be
readable by that user, and the volumes writable.

In the compose example, ofelia doesn't get the Docker socket: it goes through
`docker-api-proxy`, which allows only reading containers and starting existing
ones ([ofelia/docker-api-proxy.cfg](ofelia/docker-api-proxy.cfg)). With the
socket itself, anyone who took over ofelia would control the host. Third-party
images are pinned to exact versions; Dependabot proposes updates.

## Admin portal

Optional. Instead of editing `config/*.yaml` and the compose file to add a
share, mailbox or site, people manage sources in a web portal, and you can
hand parts of that to other teams without giving them the YAML, the server
or the crawl account.

```sh
# in .env: WORKER_TOKEN, and LDAP_* with SUPER_ADMIN_GROUPS (see .env.example)
docker compose -f docker-compose.example.yml -f docker-compose.admin.yml up -d
```

The portal is on <http://localhost:8091>. On first start it imports the
sources and settings in `config/shares.yaml`, `exchange.yaml` and
`sharepoint.yaml`; after that the portal is where they live (changes to the
files are ignored). Leaving out `docker-compose.admin.yml` goes back to the
YAML files and ofelia.

**What it does**

- **Sources**: add, edit, disable or remove SMB shares, Exchange mailboxes
  and SharePoint sites; *Test connection* signs in as the crawler would and
  reads a little, without indexing. A source's name and location (server,
  share and folder; mailbox; site URL) are fixed once it's created, since
  every document carries them: add a new source and remove the old one
  instead.
- **Removing a source** shows how many documents it has, asks for its name,
  then deletes its documents from the index and its crawl state. *Disable*
  stops crawling but leaves the documents searchable.
- **Schedules**: each source has its own crawl interval (and, for SMB, a
  permission sync interval), or manual only; *Crawl now* queues one.
- **Delegation** with *scopes*: a super admin creates a scope, names the AD
  groups that manage it, and sets its limits: which source types, which SMB
  servers and crawl accounts, which extra access its mail and SharePoint
  sources may grant, and the shortest schedule. Members of those groups see
  and manage only that scope's sources. A scope can't send the crawl
  account's credentials to a server you didn't list, or make documents
  visible to people you didn't allow (Microsoft 365 group overrides are
  super-admin only).
- **Audit log** of every change, with the before and after; scoped admins
  see their scopes' entries.
- **Activity**: queued, running and recent jobs with their output and
  running totals, and the workers' last check-in.
- **Storage**: index size, disk, growth, and each source's documents and
  estimated share of the index, read with the `pelican-status` account and
  refreshed every 15 minutes (`STORAGE_REFRESH_SECONDS`). Growth history is
  kept in `admin-data`. Scoped admins see only their own sources' rows.

**How it fits together**

- `admin` (image `pelican-admin`) holds the sources, scopes and schedules in
  SQLite on the `admin-data` volume. It has no SMB, Graph or OpenSearch
  write credentials: sources name the environment variables that hold
  them, as the YAML does. Credential profiles (Credentials page) map a name
  to `user_env` / `pass_env` / `domain_env`; set those variables on every
  worker.
- `worker` (the `pelican` image, `run_worker.py`) asks the portal for due
  jobs with `WORKER_TOKEN` and runs the usual one-shot scripts, each with a
  YAML file holding only its source. It replaces the per-job containers and
  ofelia's crawl jobs, and reuses their state volumes, so nothing is
  re-crawled. To crawl more at once, allow more jobs per worker on the
  Activity page (2 by default; super admins set the default and can give a
  worker its own number, up to 16), or add workers with `--scale worker=N`.
  Workers on other hosts (with `ADMIN_URL` pointing at the portal) work, but
  each host keeps its own crawl state, so a source whose jobs move between
  hosts is crawled again from scratch. A job whose worker stops checking in for two
  minutes is marked failed and runs again on schedule. Workers show on the
  Activity page under their Compose name (`pelican-worker-1`, `-2`, ...);
  set `WORKER_NAME` for one elsewhere, different for each worker. One not
  heard from for an hour leaves the list.
- The portal writes `shares.yaml`, `exchange.yaml` and `sharepoint.yaml`
  with every source to the `admin-export` volume. The mailbox permission
  export reads `exchange.yaml` from there, and Frogmouth can mount it for
  its SMB downloads (`downloads.smb.shares_file`).
- Sign-in is against AD (`LDAP_URL`, `LDAP_BIND_TEMPLATE`, `LDAP_BASE_DN`;
  `ldaps://` or `LDAP_START_TLS=true`, with `LDAP_CA_FILE` for a private
  CA). Members of `SUPER_ADMIN_GROUPS` are super admins; anyone else signs in only
  if a scope names one of their groups. `ADMIN_BREAKGLASS_PASSWORD` adds a
  local super admin, `pelican-admin`, for first setup or a directory outage.
  The page is plain HTTP: put it behind an HTTPS reverse proxy and set
  `ADMIN_SECURE_COOKIE=true`.
- The *Settings* page edits each type's global settings (everything in its
  YAML file except the source list) as YAML, super admins only.

Not managed in the portal: `config/pelican.yaml`, OpenSearch, and the
Exchange permission export's own schedule (ofelia keeps that one job).

## OpenSearch security

The index holds the full text of everything crawled, and the `role` field
only protects it when queries go through a search UI that applies it.
Anyone who can query OpenSearch directly sees everything, so the cluster
itself must require a sign-in.

The compose example sets this up:

- **`opensearch-certs`** creates a private CA, a certificate for the
  `opensearch` host and an admin client certificate in the `certs` volume
  on first start. OpenSearch serves HTTPS only. The CA's key isn't kept;
  to re-issue the certificates (they're valid for 10 years), remove the
  `certs` volume.
- **OpenSearch** starts with [opensearch/opensearch.yml](opensearch/opensearch.yml)
  and an empty user list ([opensearch/internal_users.yml](opensearch/internal_users.yml)).
  The image's demo setup is disabled: its certificates and demo users'
  passwords are the same in every copy of the image.
- **`opensearch-users`** signs in with the admin certificate and creates one
  account per component, each limited to the `documents` index:

  | Account | Password in `.env` | Can |
  | --- | --- | --- |
  | `pelican` | `OS_PASSWORD` | create the index, write, update and delete documents. Not delete the index |
  | `pelican-status` | `OS_STATUS_PASSWORD` (needed by the admin portal) | search, index and disk stats. For the portal's Storage page |
  | `pelican-reader` | `OS_READER_PASSWORD` (optional) | search. For Frogmouth or another UI |
  | `admin` | `OS_ADMIN_PASSWORD` (optional) | everything. For you |

  It runs on every `docker compose up`, so a changed password takes effect
  on the next one.

A search UI on the same Docker network connects to
`https://opensearch:9200` as `pelican-reader`, trusting the CA in the
`certs` volume (`ca.pem`).

To use your own cluster instead, remove the three OpenSearch services and
set `OS_HOST`, `OS_USERNAME`, `OS_PASSWORD` and, unless its certificate is
from a public CA, `OS_CA_CERTS`. Give the crawler account the permissions
in [pelican/opensearch_setup.py](pelican/opensearch_setup.py).

**Already running the 0.1.x compose example?** Its OpenSearch has no
security. Copy the new `docker-compose.example.yml` and `opensearch/`
folder, add the `OS_*_PASSWORD` values to `.env`, and run
`docker compose up -d`. The existing index is kept. Search UIs then need
the new address, sign-in and CA.

## Backups

The compose example snapshots the index every night (02:00 in `TZ`, keeping
the last 14) into the `opensearch-snapshots` volume. OpenSearch runs the
schedule itself; the `opensearch-users` job sets it up from
`OS_SNAPSHOT_SCHEDULE` (cron, or `off`) and `OS_SNAPSHOT_KEEP` in `.env`.

That volume is on the same disk as the index, so it protects against
mistakes and corruption, not a failed disk. Copy it off the host, or mount
other storage there instead (in `docker-compose.example.yml`).

Signed in as `admin`:

```sh
# list snapshots
curl -sk -u admin https://localhost:9200/_cat/snapshots/pelican-backups?v
# restore one (stop the crawlers and delete or close the index first)
curl -sk -u admin -XPOST -H 'Content-Type: application/json' \
  https://localhost:9200/_snapshot/pelican-backups/<snapshot>/_restore \
  -d '{"indices": "documents"}'
```

Run these from inside the OpenSearch container (`docker compose exec
opensearch ...`); port 9200 isn't published. The crawlers' state volumes
aren't snapshotted: if one is lost, that crawler re-indexes its sources on
its next run.

## Vector search

Optional, and off by default. With it on, OpenSearch splits each document's
text into passages of about 300 words as it's indexed, embeds them with an
English model (`BAAI/bge-base-en-v1.5` by default), and stores one vector
per passage. A search UI can then find documents by meaning as well as by
words (Frogmouth's Semantic and Hybrid modes). The crawlers don't change:
everything happens in OpenSearch's ingest pipeline.

To turn it on, before the first crawl, add to `.env`:

```sh
VECTOR_ENABLED=true
COMPOSE_PROFILES=vector                    # starts the embeddings service
EMBEDDINGS_API_KEY=<long random string>    # e.g. openssl rand -hex 24
OS_HEAP=4g                                 # OpenSearch heap; see below
```

The `embeddings` service runs Hugging Face Text Embeddings Inference, on
the CPU by default. With an NVIDIA GPU (driver and Container Toolkit on the
host), add [docker-compose.gpu.yml](docker-compose.gpu.yml), e.g.
`COMPOSE_FILE=docker-compose.example.yml:docker-compose.gpu.yml` in `.env`,
and set `EMBEDDINGS_IMAGE` if your card isn't an RTX 30xx (the file lists
the image per GPU generation). A GPU makes a large difference: an RTX 3070
embeds a few hundred passages a second.

`opensearch-users` then connects OpenSearch to the service (only
OpenSearch has its key), creates the `pelican-embed` ingest pipeline and
the `pelican-search` search pipeline, and gives `pelican` and
`pelican-reader` the two ML permissions they need (to read and call the
model). On first start it waits up to 15 minutes while the service
downloads the model. Each run replaces the model and its connector with
fresh ones.

Things to know:

- **New index only.** The index is created with the vector fields and
  pipelines; an existing index keeps its mapping, and crawlers log a warning
  if vector search is on but the index has none. To add vectors, delete the
  index and the crawlers' state volumes, then crawl again. Changing the
  model or `dimension` needs the same.
- **Only the start of long documents is embedded:** up to `max_chunks`
  passages (100 by default, about 30,000 words). All of the text stays
  searchable by keyword.
- **Access changes don't re-embed.** The ACL sync's role updates go through
  the pipeline, which reuses a document's stored vectors when its text
  hasn't changed. A changed file is embedded again.
- **OpenSearch needs more memory.** Re-indexing a changed document holds
  its stored text and vectors alongside the new ones, so a crawl that
  re-indexes large files can trip OpenSearch's memory limit at the default
  2 GB heap. Set `OS_HEAP` to 4g or more (half the host's free RAM at most).
  Pelican also sends bulk writes in requests of at most `BULK_MAX_MB` (10)
  and retries any OpenSearch refuses for memory, after a pause.
- **The embeddings service is now in the indexing path.** If it's down,
  bulk writes fail and the crawl reports the share as failed, to be retried
  on the next run.
- **Searches must filter inside the vector query.** Put the role filter in
  the `neural` query's `filter`, not only around it: otherwise the nearest
  passages can all belong to documents the user can't see, and they get
  too few results or none. The search pipeline supplies the model, so
  queries don't name it.

Settings are under `vector:` in `config/pelican.yaml`.

## Index contract

Any search UI reading the index must agree with `config/pelican.yaml`:

- **Roles.** A document's `role` field lists who may see it, as
  `<prefix><name>`: users `1<username>` (lower-cased), AD groups `2<group CN>`,
  named roles `R<role>`. `Rguest` marks content open to every signed-in
  user. The UI must build each user's roles the same way and filter every
  query on them.
- **Sources.** `host` is `smb-share`, `exchange-online` or
  `sharepoint-online`; `share` is the share, mailbox or site name.
- **Index.** `opensearch.index`, created with `search_index_mapping.json` on
  first run.
- **Vectors** (only with vector search on). `content_embedding_mean` is one vector for the whole document, the average of its passages. `content_embedding` is a nested
  field with one `{"knn": [...]}` object per passage of `content`; the
  index's default search pipeline fills in the model for `neural` queries
  and blends `hybrid` query scores.

Changing prefixes or `host` values on an existing index needs a full re-crawl.

## Project layout

```
crawl_smb.py, sync_smb_acl.py,     job entry points
crawl_exchange.py, crawl_sharepoint.py
check_source.py, purge_source.py   connection test, source removal
run_worker.py                      worker for the admin portal
pelican/                           shared core
  settings.py                      config loading
  index.py                         OpenSearch client, schema, bulk writes
  state.py                         incremental-crawl state (SQLite)
  roles.py                         role encoding, re-applying access changes
  smb_shares.py, smb_acl.py        SMB config, connections, ACLs
  graph_client.py                  Microsoft Graph client
  extract_text.py                  text and metadata extraction
  status.py, watchdog.py           progress reporting, hang protection
  opensearch_setup.py              certificates, accounts and vector search
                                   setup (compose example)
config/                            example configuration
search_index_mapping.json          index mapping
requirements.in                    direct dependencies; requirements.txt is
                                   the pinned, hashed lock (pip-compile)
exo-permissions/                   separate image
admin/                             admin portal image (store.py: rules,
                                   scheduler; admin_server.py: web/API;
                                   storage.py: storage figures)
opensearch/                        OpenSearch security config (compose example)
ofelia/                            Docker API proxy config for the scheduler
tests/integration/                 end-to-end test (run.sh)
tests/admin/                       admin portal and worker unit tests
```

## Testing

```sh
tests/integration/run.sh
VECTOR=1 tests/integration/run.sh     # the same, with vector search on
```

builds the images from your checkout and runs the compose example with a
test Samba server: a real SMB crawl (text, Word and PDF extraction, photo
EXIF and GPS, ACL roles, exclusions), the ACL sync, every OpenSearch account's permissions,
snapshots, the scheduler proxy, and the admin portal with a worker (import,
test connection, crawl, adding a source and removing it with its documents,
storage figures). It uses its
own project name, volumes and ports, so it can run next to a real
deployment. With `VECTOR=1` it also starts the CPU embeddings service
(downloading the model, about 450 MB, each run) and checks that every
fixture is embedded, that a role-filtered neural query as `pelican-reader`
finds exactly what those roles allow, and that a role change doesn't
re-embed anything. GitHub Actions runs it before building any image, including
on Dependabot's pull requests.

The admin portal's rules (delegation limits, scheduling, removal) and the
worker have unit tests that need only Python, pyyaml, ldap3 and requests:

```sh
python -m unittest discover -s tests/admin
```

## AI disclosure

Much of this code was written with AI assistance (Anthropic's Claude), then
reviewed and tested by the maintainers.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE)
for attribution.
