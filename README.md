# Pelican

Permission-aware crawlers that feed an OpenSearch index from **SMB file
shares**, **Exchange Online mailboxes** and **SharePoint Online sites**.

Each document carries access roles taken from its source's own permissions
(SMB folder ACLs, mailbox Full Access, Microsoft 365 group membership), so a
search front end can show every user only what they're allowed to see. All
crawlers write one shared schema into one index; Frogmouth is a companion
search UI built for it.

## Features

- **SMB** via pysmb (no host mounts): parallel fetch, incremental by
  modification time, deletion detection with guards against wiping a share
  on a bad listing, and per-folder ACLs via `smbcacls` with a separate job that
  re-applies permission changes without re-downloading anything.
- **Exchange Online** via Microsoft Graph delta queries: full MIME per message,
  attachment text, Full Access holders mapped to AD accounts.
- **SharePoint Online** via Graph with `Sites.Selected` (only the sites you
  grant): delta queries per library, extension whitelist, site group members
  mirrored as access.
- **Text extraction** for PDF (isolated, with a timeout), DOCX, EML/MSG
  (including attachments) and plain text; EXIF camera and GPS data for images,
  reverse-geocoded offline.
- **Fail-closed access**: if permissions can't be read, new content is
  restricted and existing content keeps its last known access.
- **Built for unattended runs**: one-shot jobs, a process watchdog for silent
  network hangs, and a status page showing every job and index growth.

## Quick start

Requires Docker with Compose.

```sh
cp .env.example .env                      # credentials, OpenSearch passwords
$EDITOR config/shares.yaml                # and/or exchange.yaml, sharepoint.yaml
docker compose -f docker-compose.example.yml up -d
```

This pulls the published images from `ghcr.io/silcrats` (`pelican`,
`pelican-status`, `pelican-exo-permissions`). Set `PELICAN_VERSION` in `.env`
to pin a release, or add `--build` to build from your checkout instead.

The example runs a single-node OpenSearch with its security plugin on (see
[OpenSearch security](#opensearch-security)), one container per job
scheduled by [ofelia](https://github.com/mcuadros/ofelia), and the status
page on <http://localhost:8090>. Remove the services you don't need.

Each crawler is a one-shot process: it crawls once and exits. The image
defaults to `crawl_smb.py`; choose another job with an entrypoint override.

| Job | Purpose | Config |
| --- | --- | --- |
| `crawl_smb.py` | SMB shares → index | `config/shares.yaml` |
| `sync_smb_acl.py` | Re-check SMB folder ACLs, update roles on indexed docs | `config/shares.yaml` |
| `crawl_exchange.py` | Exchange Online mailboxes → index | `config/exchange.yaml` |
| `crawl_sharepoint.py` | SharePoint Online sites → index | `config/sharepoint.yaml` |
| `exo-permissions/` | Export mailbox Full Access holders (PowerShell) | `config/exchange.yaml` |
| `status-page/` | Always-on status page | -- |

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
| `JOB_NAME`, `STATUS_DIR` | `primary`, `/status` | Status file name and location |
| `SHARE_NAMES`, `MAILBOX_NAMES`, `SITE_NAMES` | all | Comma-separated subset for this container, to split work across containers |
| `TZ` | UTC | Time zone for status timestamps |

Tuning (all optional): `BATCH_SIZE`, `SMB_WORKERS`, `GRAPH_WORKERS`,
`SP_WORKERS`, `ACL_SYNC_WORKERS`, `ACL_RECHECK_HOURS`, `PDF_TIMEOUT_SECONDS`,
`WATCHDOG_TIMEOUT_SECONDS`, `SMB_CONNECT_TIMEOUT_SECONDS`,
`SMB_LIST_TIMEOUT_SECONDS`, `SMB_FETCH_TIMEOUT_SECONDS`,
`SMB_LIST_STALL_SECONDS`, `GRAPH_MAX_RETRIES`.

The crawler and status images run as UID 10001, not root. Anything you
mount (config, `secrets/`, state and status volumes) must be readable by that
user, and the state and status volumes writable.

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
  | `pelican-status` | `OS_STATUS_PASSWORD` | search, index and disk stats |
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

Changing prefixes or `host` values on an existing index needs a full re-crawl.

## Project layout

```
crawl_smb.py, sync_smb_acl.py,     job entry points
crawl_exchange.py, crawl_sharepoint.py
pelican/                           shared core
  settings.py                      config loading
  index.py                         OpenSearch client, schema, bulk writes
  state.py                         incremental-crawl state (SQLite)
  roles.py                         role encoding, re-applying access changes
  smb_shares.py, smb_acl.py        SMB config, connections, ACLs
  graph_client.py                  Microsoft Graph client
  extract_text.py                  text and metadata extraction
  status.py, watchdog.py           progress reporting, hang protection
  opensearch_setup.py              certificates and accounts (compose example)
config/                            example configuration
search_index_mapping.json          index mapping
requirements.in                    direct dependencies; requirements.txt is
                                   the pinned, hashed lock (pip-compile)
status-page/, exo-permissions/     separate images
opensearch/                        OpenSearch security config (compose example)
```

## AI disclosure

Much of this code was written with AI assistance (Anthropic's Claude), then
reviewed and tested by the maintainers.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE)
for attribution.
