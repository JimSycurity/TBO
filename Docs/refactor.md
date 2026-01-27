# Titanis → TBO refactor inventory (Titanis‑rmf.1)

## Inventory (changes outside TBO module that TBO depends on)

### SMB core
- Smb2Client.cs: new RequiredCreateOptions, reauth loop using RequiresReauth, plus DisconnectServerAsync/DisconnectAllAsync.
- Smb2Session.cs: adds RequiredCreateOptions + RequiresReauth.
- Smb2TreeConnect.cs: applies RequiredCreateOptions to all creates.
- Smb2ConnectionOptions.cs + Smb2Connection.cs: AllowZeroCreditFallback opt‑in.
- Smb2OpenFileObjectBase.cs: SetSecurityAsync helper.
- Smb2SetInfoRequest.cs: security descriptor info + Additional flags.
- AssemblyInfo.cs: InternalsVisibleTo("Titanis.TBO.Smb2.PowerShell").

### MS‑RRP (Remote Registry)
- New project src/net/msrpc/Titanis.Msrpc.Msrrp/* and CLI tools/rpc/Reg/* + Reg.md.
- RegistryKey.GetSubkeyNames() now falls back when QueryInfo is denied (HKU fix).

### Security / SAM
- New src/base/Titanis.Winterop.Sam/* and multiple src/net/msrpc/Titanis.Msrpc.Mssamr/* updates for richer SAM info handling.

### RPC / Core
- RpcExtensions.cs added (old RpcExtensions.cs removed).
- TicketAuthorizationData.cs updated to use ToRpcUnicodeString.
- src/net/msrpc/Titanis.Msrpc.Mslsar/* adds LSA account access overload.

### Bug fixes / helpers
- SecurityDescriptor.cs fixes SACL offset + 8‑byte alignment.
- BinaryHelper.cs + StringHelper.cs add hex/escape helpers.

### Build / solution
- No Titanis build/solution deltas remain (reverted to trustedsec/feature/ms-rrp).

### TBO‑specific files to move
- src/**
- Titanis.TBO.Smb2.PowerShell.Tests.ps1
- PowerShellSmb2Registry.md
- .beads/*, AGENTS.md removed from Titanis (as agreed).

## Behavior changes / gating candidates

### SMB create‑options injection
- Smb2Client.RequiredCreateOptions + Smb2TreeConnect auto‑adds create options to all opens.
- Impact: changes behavior only if RequiredCreateOptions is set (TBO does).
- Gating: keep default None (already), document as opt‑in upstream.

### SMB reauth loop (backup‑priv auto‑grant)
- RequiresReauth is set by TBO to force reconnect after LSA privilege changes.
- Impact: no behavior change unless set.
- Gating: keep RequiresReauth internal + InternalsVisibleTo for TBO. Upstream PR can note it’s for optional reauth workflows.

### Zero‑credit fallback
- AllowZeroCreditFallback is opt‑in and only used for winreg RPC enumeration.
- Impact: no change unless enabled.
- Gating: keep opt‑in and document.

### Registry HKU enumeration fallback
- RegistryKey.GetSubkeyNames fallback avoids QueryInfo on access denied.
- Impact: changes enumeration behavior in msrrp library, but improves reliability.
- Gating: likely unnecessary.

Everything else is additive or bug‑fix (good PR candidates).

## Upstream comparison (trustedsec/feature/ms-rrp)

I added the trustedsec remote and compared against trustedsec/feature/ms-rrp.

### Already in upstream
- tools/rpc/Reg
- SAM additions

### Remaining deltas vs trustedsec/feature/ms-rrp
- TBO module + tests + docs + beads + AGENTS.md
- PowerShellSmb2Registry.md (+ index entry)
- SecurityDescriptor fixes (SACL offset, 8‑byte alignment)
- SMB core additions: RequiredCreateOptions/RequiresReauth, AllowZeroCreditFallback, disconnect helpers, SetSecurityAsync + security descriptor info
- InternalsVisibleTo("Titanis.TBO.Smb2.PowerShell")
- LSA CreateAccount access overload
- MS‑RRP RegistryKey enumeration fallback + RemoteRegistryClient changes

## Justification notes (Titanis deltas required for TBO)
- SecurityDescriptor.cs: fix SACL offset and 8‑byte alignment to avoid corrupt SD parsing (bug fix).
- Smb2Client/Session/TreeConnect: RequiredCreateOptions + RequiresReauth enable backup‑intent opens and privilege re‑auth for TBO.
- Smb2ConnectionOptions/Connection: AllowZeroCreditFallback improves named‑pipe RPC reliability (TBO winreg enumeration).
- Smb2OpenFileObjectBase + Smb2SetInfoRequest: SetSecurityAsync + SecurityDescriptorInfo enable SD write‑back over SMB2.
- AssemblyInfo.cs: InternalsVisibleTo exposes required internals to the TBO PowerShell module.
- LsaClient/LsaPolicy: CreateAccount access overload allows TBO to request specific access masks.
- Msrrp RegistryKey + RegistryKey.Mutations: add create/delete/set value support and access‑denied‑safe enumeration for TBO provider.
- RemoteRegistryClient: HostU service class binding required for TBO remote registry auth.

I left a detailed comment on Titanis‑rmf.1 with this summary.

## Dependency wiring (TBO repo)
- TBO uses ProjectReference to Titanis projects when TitanisRepoRoot is set.
- Set TITANIS_REPO or TitanisRepoRoot to point at the Titanis repo for local development.
- Default assumes sibling path ..\Titanis.
