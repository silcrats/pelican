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
cp .env.example .env                      # credentials
$EDITOR config/shares.yaml                # and/or exchange.yaml, sharepoint.yaml
docker compose -f docker-compose.example.yml up -d --build
```

The example runs a single-node OpenSearch (security disabled), one container
per job scheduled by [ofelia](https://github.com/mcuadros/ofelia), and the
status page on <http://localhost:8090>. Remove the services you don't need.

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
| `STATE_DB_PATH` | `/state/pelican_state.db` | Incremental state. One volume per crawler; an SMB crawler and its ACL sync share one |
| `JOB_NAME`, `STATUS_DIR` | `primary`, `/status` | Status file name and location |
| `SHARE_NAMES`, `MAILBOX_NAMES`, `SITE_NAMES` | all | Comma-separated subset for this container, to split work across containers |
| `TZ` | UTC | Time zone for status timestamps |

Tuning (all optional): `BATCH_SIZE`, `SMB_WORKERS`, `GRAPH_WORKERS`,
`SP_WORKERS`, `ACL_SYNC_WORKERS`, `ACL_RECHECK_HOURS`, `PDF_TIMEOUT_SECONDS`,
`WATCHDOG_TIMEOUT_SECONDS`, `SMB_CONNECT_TIMEOUT_SECONDS`,
`SMB_LIST_TIMEOUT_SECONDS`, `SMB_FETCH_TIMEOUT_SECONDS`,
`SMB_LIST_STALL_SECONDS`, `GRAPH_MAX_RETRIES`.

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
config/                            example configuration
search_index_mapping.json          index mapping
status-page/, exo-permissions/     separate images
```

## AI disclosure

Much of this code was written with AI assistance (Anthropic's Claude), then
reviewed and tested by the maintainers.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE)
for attribution.
