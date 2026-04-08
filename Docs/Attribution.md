# Attribution

This document records known external sources of code or ideas referenced in TBO and their licenses.
Reviewed: 2026-02-06. Updated: 2026-04-07 (added Bad-Jubies MS-BKRP padding-oracle reference).

**Sources**
- SharpDPAPI (GhostPack) — referenced in `README.md` for DPAPI/CredMan/CredVault behaviors. License: BSD-3-Clause. Source: https://github.com/GhostPack/SharpDPAPI (license: https://raw.githubusercontent.com/GhostPack/SharpDPAPI/master/LICENSE)
- BackupOperatorToolkit — referenced in `README.md` and `Docs/DevGuide/PowerShellSmb2Registry.md` for SMB/registry behavior. License: no LICENSE file detected in the repository as of 2026-02-06; treat as all rights reserved until clarified. Source: https://github.com/improsec/BackupOperatorToolkit
- DPAPIck — DPAPI master key layout/crypto flow reference noted in `src/DpapiMasterKeyCrypto.cs`. License: GPL-3.0. Source: https://www.tarlogic.com/blog/cracking-windows-credentials-dpapi-part-ii/
- DPAPImk2john (John the Ripper) — DPAPI master key layout reference noted in `src/DpapiMasterKeyCrypto.cs`. License: GPL-2.0-or-later. Source: https://github.com/openwall/john (licensing: https://www.openwall.com/wiki/john/licensing)
- Bad-Jubies/Exploits "MS-BKRP_padding_oracle_decrypt.py" — Python reference implementation of the Bleichenbacher '98 padding-oracle attack against MS-BKRP. Informed the oracle return-code mapping (0x0 / 0x0d / 0x57), the AccessCheck-zeroing trick that keeps PKCS#1 padding validation reachable while forcing the inner SID check to fail, the BackupKey/RestoreKey action GUIDs, and the bare-conformant-array marshalling of `pDataIn` (no `[unique]` referent ID despite the IDL). Referenced in `src/BleichenbacherOracle.cs` and `src/BkrpClient.cs`. License: no LICENSE file detected in the repository as of 2026-04-07; treat as all rights reserved until clarified. Source: <https://github.com/Bad-Jubies/Exploits/blob/main/MS-BKRP_padding_oracle_decrypt.py>

**Most Restrictive Open Source License**

- GPL-3.0 (DPAPIck) is the most restrictive open source license among the sources listed above. Note: the Bad-Jubies repository has no detected LICENSE file as of 2026-04-07 — until clarified, that source must be treated as all-rights-reserved, which is more restrictive than GPL-3.0 in practice.
