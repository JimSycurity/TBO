# Winreg Session Caching

This module caches a winreg RPC session per server to reduce STATUS_PIPE_BUSY churn and improve performance for high-volume registry cmdlets.

## How it works
- Cache key: server + port + connection fingerprint (credentials and connection options).
- A single cached session is reused per key; access is serialized with a semaphore to avoid concurrent use of the same RPC stream.
- If the cached session is invalidated, the next registry operation opens a fresh session automatically.

## Invalidation triggers
- `Disconnect-TBOSmbServer` / `DisconnectAll` purges cached winreg sessions.
- `Set-TBOSmbConnectOptions` / `Set-TBORegConnectOptions` changes that alter the fingerprint drop the cached session.
- `RegistryRetryHelper` invalidates the cache on `STATUS_PIPE_BUSY` or transport exceptions before retrying.
- Any RPC disposal/transport failure that bubbles out of a cached session will cause invalidation.

## User-visible behavior
- Cmdlet usage is unchanged; caching is transparent.
- Diagnostic logs include cache invalidation reasons when diagnostics are enabled.
- If you suspect a stale session, run `Disconnect-TBOSmbServer -Force` and retry.

## Notes
- One cached session per server is the default to keep the RPC stream single-threaded and avoid pipe churn.
- A small pool could be introduced later if parallelism becomes a requirement.
