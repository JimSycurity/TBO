# Agent Instructions

Use an object‑oriented, reusable design: factor shared logic into small, well‑named helpers or classes and avoid duplicated implementations across cmdlets.

TBO module and all cmdlets must have Help (per https://learn.microsoft.com/en-us/powershell/scripting/developer/help/writing-help-for-windows-powershell-modules?view=powershell-7.5) and be documented with examples before committing. Cmdlet usage examples belong in Docs/Usage.md

This project uses **bd** (beads) for issue tracking. Run `bd onboard` to get started.

## Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --status in_progress  # Claim work
bd close <id>         # Complete work
bd sync               # Sync with git
```

**Issues with `TestReq` Label** must be tested and approved by human before closing issue or committing.

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items, add detailed comments of work done to issues
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd sync
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

Note: Commit signing is configured, allow time for human interaction with passphrase. **DO NOT USE `commit.gpgsign=false`!**

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds

