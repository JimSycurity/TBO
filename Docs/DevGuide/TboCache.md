# TBO Cache (Principals + Credentials)

## Overview

TBO discovers security principals and credentials while triaging local and remote machines (SAM hashes, cached logons, LSA secrets, DPAPI material, browser credentials, etc). This document defines a persistent, additive cache stored on disk so that discoveries from multiple sessions and multiple hosts can be correlated.

Primary initial use case: detect credential reuse across hosts by comparing normalized identifiers such as NT hashes.

## Goals

- Persist state on disk between PowerShell sessions.
- Additive ingestion: new observations append; existing entities are de-duplicated (upsert) where possible.
- Correlate by stable identifiers:
  - Principals: SID (when known), plus name hints.
  - Credentials: kind + normalized identifier (ex: NTHash hex, DCC2 hex).
  - Machines: `ServerName` and optional name aliases.
- Query surfaces for triage:
  - "What did we find on host X?"
  - "Where else was this hash seen?"
  - "What principals are linked to these credentials?"
- Keep the storage layer internal and boring so cmdlets can evolve without schema churn.

## Non-goals (Initial)

- Distributed/synchronized cache across multiple operators.
- Full fidelity logon event modeling.
- BloodHound OpenGraph-specific export (tracked as follow-on).

## Storage Backend

Default backend: SQLite via `Microsoft.Data.Sqlite` (already used in `Get-TBOChrome*` cmdlets).

Rationale:

- Single portable file, easy to inspect and query.
- Supports indexes and relational joins needed for correlation queries.
- WAL mode supports multiple readers and single-writer concurrency across PowerShell sessions.

Alternatives (deferred): DuckDB, JSONL.

## Cache Path Resolution

Cache should be per-user by default and overridable for portability.

Proposed resolution order:

1. `-Path` parameter on cache cmdlets (explicit).
2. `TITANIS_TBO_CACHE` environment variable:
   - If set to a file path, use it.
   - If set to `1/true/yes`, use the default path.
3. Default path:
   - Windows: `%LOCALAPPDATA%\\TBO\\cache.sqlite3`
   - Non-Windows: `$HOME/.tbo/cache.sqlite3`

Implementation should ensure the parent directory exists and fail with a clear message when the path is invalid/unwritable.

## Secret Storage Policy

This cache is intended for correlation. Persisting cleartext secrets to disk is high risk.

Baseline policy:

- Always store identifiers needed for correlation (hashes, GUIDs, SIDs) in normalized form.
- Do not persist cleartext secrets by default.

Optional policy (future, behind an explicit opt-in):

- Persist cleartext secrets encrypted at rest.
  - Windows: DPAPI user-scope (CurrentUser) is the simplest default.
  - Cross-platform: do not store cleartext unless a passphrase/key mechanism is provided.

## Data Model (Proposed)

This model is intentionally small and centered on observations.

Entities:

- `machines` (the target host context)
  - Unique key: normalized `ServerName` (for now), with optional alias table later.
- `principals` (user/computer/service accounts)
  - Unique key: SID when available, otherwise a best-effort `(domain, name, type)` key.
- `credentials` (hashes/keys/secrets)
  - Unique key: `(kind, identifier)` where `identifier` is a normalized string (usually hex).
- `observations` (edges)
  - Links a `machine` to an observed `principal` and/or `credential`, with source metadata.

Example schema sketch (not final SQL):

```sql
machines(
  machine_id INTEGER PRIMARY KEY,
  server_name TEXT NOT NULL UNIQUE COLLATE NOCASE,
  first_seen_utc TEXT NOT NULL,
  last_seen_utc TEXT NOT NULL
);

principals(
  principal_id INTEGER PRIMARY KEY,
  sid TEXT NULL UNIQUE COLLATE NOCASE,
  domain TEXT NULL,
  name TEXT NULL,
  type TEXT NULL, -- user/computer/group/service/unknown
  first_seen_utc TEXT NOT NULL,
  last_seen_utc TEXT NOT NULL
);

credentials(
  credential_id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL, -- nthash/lmhash/dcc2/cleartext/...
  identifier TEXT NOT NULL, -- normalized
  secret_blob BLOB NULL,    -- optional encrypted cleartext (future)
  first_seen_utc TEXT NOT NULL,
  last_seen_utc TEXT NOT NULL,
  UNIQUE(kind, identifier)
);

observations(
  observation_id INTEGER PRIMARY KEY,
  machine_id INTEGER NOT NULL REFERENCES machines(machine_id),
  principal_id INTEGER NULL REFERENCES principals(principal_id),
  credential_id INTEGER NULL REFERENCES credentials(credential_id),
  source_kind TEXT NOT NULL, -- SAM/LSA/CachedLogons/CredMan/Chrome/Manual/...
  source_path TEXT NULL,     -- registry path, file path, etc
  observed_utc TEXT NOT NULL,
  context_json TEXT NULL,    -- small extra metadata
  confidence INTEGER NULL    -- 0-100
);
```

Normalization:

- SID: canonical SDDL string (ex: `S-1-5-21-...`), case-insensitive.
- Hash identifiers: uppercase hex, no separators.
- `ServerName`: case-insensitive; keep original input separately if useful.

## Concurrency

When using SQLite:

- Enable WAL mode (`PRAGMA journal_mode=WAL`).
- Set a short busy timeout (ex: 2-5 seconds) to handle transient writer contention.
- Keep transactions short.

## Cmdlet Surface (Initial)

Management:

- `Get-TBOCacheInfo` (path, schema version, row counts)
- `Clear-TBOCache` (delete all rows)
- `Remove-TBOCacheEntry` (targeted delete)

Queries:

- `Get-TBOCacheCredentialReuse` (ex: NTHash seen on multiple machines)
- `Get-TBOCacheMachineFindings` (inventory by host)

Ingestion:

- An internal API (and possibly a cmdlet) like `Add-TBOCacheObservation` to avoid duplicating DB logic across cmdlets.
- Existing discovery cmdlets can later gain a `-Cache` switch (or global enable) to write observations.

## Open Questions

- OpenGraph meaning:
  - For TBO cache export, OpenGraph means the BloodHound OpenGraph schema: https://bloodhound.specterops.io/opengraph/schema
  - GraphViz DOT and generic nodes+edges JSON are still useful for quick visualization and are implemented.
- Caching enablement:
  - Prefer a global toggle to enable observation ingestion by default, while still allowing per-cmdlet overrides.

## Principal Identity Strategy

Schema v1 behavior:

- Primary identity: `sid` (when present). This is treated as globally unique.
- SID-less principals: best-effort identity key `(domain, name, type)` when `domain` and `name` are present. Type can be upgraded from NULL.
- Do not correlate on RID alone (for example, local Administrator is commonly RID 500).
- When a cmdlet only knows a local principal name (no SID), it should scope `domain` to the current machine (for example `ServerName`) to avoid cross-host collisions.

Known limitation:

- Some well-known/builtin SIDs are shared across machines (for example, `SYSTEM` and `BUILTIN` groups). Schema v1 treats these as global principals, which can collapse per-host local-group semantics.

Roadmap:

- Schema v2 scoped principals (Global vs Machine), with updated unique indexes and migration: `TBO-ha0.1`.
- SAM ingestion: derive full local account SIDs (machine SID + RID) and ingest `PrincipalSid`: `TBO-ha0.2`.
