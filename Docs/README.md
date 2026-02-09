# TBO Documentation

`Docs/Usage.md` is the canonical cmdlet/provider reference (lots of examples, kept current as new cmdlets land).
This folder adds a shorter, more human-readable guide and an index so people can find what they need quickly.

## Start Here

- **User guide:** [Docs/Guide.md](Guide.md)
- **Cmdlet/provider reference:** [Docs/Usage.md](Usage.md)

## Key Topics

- **Connection/session caching (winreg):** [Docs/WinregSessionCaching.md](WinregSessionCaching.md)
- **Cache internals (developer notes):** [Docs/DevGuide/TboCache.md](DevGuide/TboCache.md)
- **Secret decoding heuristics:** [Docs/SecretDecodingHelpers.md](SecretDecodingHelpers.md)
- **Build notes:** [Docs/Build.md](Build.md)
- **Release notes:** [Docs/ReleaseNotes/](ReleaseNotes/)
- **Attribution:** [Docs/Attribution.md](Attribution.md)
- **Disclaimer:** [DISCLAIMER.md](../DISCLAIMER.md)

## Keeping Docs Maintained

When a new cmdlet or behavior is added:

1. Update [Docs/Usage.md](Usage.md) (authoritative reference + examples).
2. Update [Docs/Guide.md](Guide.md) if the change affects workflows, defaults, caching, or troubleshooting.
