# Attribution

This document records known external sources of code or ideas referenced in TBO and their licenses.
Reviewed: 2026-02-06.

**Sources**
- SharpDPAPI (GhostPack) — referenced in `README.md` for DPAPI/CredMan/CredVault behaviors. License: BSD-3-Clause. Source: https://github.com/GhostPack/SharpDPAPI (license: https://raw.githubusercontent.com/GhostPack/SharpDPAPI/master/LICENSE)
- BackupOperatorToolkit — referenced in `README.md` and `Docs/DevGuide/PowerShellSmb2Registry.md` for SMB/registry behavior. License: no LICENSE file detected in the repository as of 2026-02-06; treat as all rights reserved until clarified. Source: https://github.com/improsec/BackupOperatorToolkit
- DPAPIck — DPAPI master key layout/crypto flow reference noted in `src/DpapiMasterKeyCrypto.cs`. License: GPL-3.0. Source: https://www.tarlogic.com/blog/cracking-windows-credentials-dpapi-part-ii/
- DPAPImk2john (John the Ripper) — DPAPI master key layout reference noted in `src/DpapiMasterKeyCrypto.cs`. License: GPL-2.0-or-later. Source: https://github.com/openwall/john (licensing: https://www.openwall.com/wiki/john/licensing)

**Most Restrictive Open Source License**
- GPL-3.0 (DPAPIck) is the most restrictive open source license among the sources listed above.
