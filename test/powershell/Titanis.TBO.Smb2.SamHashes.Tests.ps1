Set-StrictMode -Version Latest

$script:testHarnessPath = Join-Path $PSScriptRoot 'TboTestHarness.ps1'
if (Test-Path -LiteralPath $script:testHarnessPath) {
	. $script:testHarnessPath
}

Describe 'Get-TBORegSamHashes cache ingestion (mocked)' {
	BeforeAll {
		$testHarnessPath = Join-Path $PSScriptRoot 'TboTestHarness.ps1'
		if (Test-Path -LiteralPath $testHarnessPath) {
			. $testHarnessPath
		}

		function script:Invoke-WithMockProvider {
			param(
				[Parameter(Mandatory = $true)]
				[object]$ProviderInfo,
				[Parameter(Mandatory = $true)]
				[scriptblock]$ScriptBlock
			)

			$scope = Use-TboProviderInfoOverride -ProviderInfo $ProviderInfo
			try {
				& $ScriptBlock
			} finally {
				$scope.Dispose()
			}
		}

		function script:Get-BootKeyClassNames {
			param([Parameter(Mandatory = $true)][byte[]]$BootKey)

			if ($BootKey.Length -ne 16) {
				throw "BootKey must be 16 bytes, got $($BootKey.Length)."
				}

				# Mirrors src/RegistryBootKeyReader.cs.
				[UInt64]$swap = [UInt64]::Parse('EC6B4D50F91273A8', [System.Globalization.NumberStyles]::HexNumber)
				$indices = New-Object int[] 16
				for ($i = 0; $i -lt 16; $i++) {
					$indices[$i] = [int]($swap -band 0xF)
					$swap = $swap -shr 4
			}

			$classBytes = New-Object byte[] 16
			for ($i = 0; $i -lt 16; $i++) {
				$classBytes[$i] = $BootKey[$indices[$i]]
			}

			$names = @('JD', 'Skew1', 'GBG', 'Data')
			$result = @{}
			for ($k = 0; $k -lt 4; $k++) {
				$slice = $classBytes[($k * 4)..($k * 4 + 3)]
				$result[$names[$k]] = ($slice | ForEach-Object { $_.ToString('x2') }) -join ''
			}

			return $result
		}

		function script:New-SamAccountFBytes {
			param(
				[Parameter(Mandatory = $true)][byte[]]$SysKey,
				[Parameter(Mandatory = $true)][byte[]]$MasterKey,
				[Parameter(Mandatory = $true)][byte[]]$Salt
			)

			if ($SysKey.Length -ne 16) { throw "SysKey must be 16 bytes, got $($SysKey.Length)." }
			if ($MasterKey.Length -ne 16) { throw "MasterKey must be 16 bytes, got $($MasterKey.Length)." }
			if ($Salt.Length -ne 16) { throw "Salt must be 16 bytes, got $($Salt.Length)." }

			$aes = [System.Security.Cryptography.Aes]::Create()
			try {
				$aes.Key = $SysKey
				$cipher = $aes.EncryptCbc($MasterKey, $Salt)
			} finally {
				$aes.Dispose()
			}

			$f = New-Object byte[] (136 + $cipher.Length)
			[Array]::Copy([BitConverter]::GetBytes([UInt32]2), 0, $f, 104, 4)  # revision
			[Array]::Copy([BitConverter]::GetBytes([Int32]$cipher.Length), 0, $f, 116, 4)  # cbData
			[Array]::Copy($Salt, 0, $f, 120, 16)
			[Array]::Copy($cipher, 0, $f, 136, $cipher.Length)
			return ,$f
		}

		function script:New-DomainSidBytes {
			param(
				[Parameter(Mandatory = $true)][UInt32]$A,
				[Parameter(Mandatory = $true)][UInt32]$B,
				[Parameter(Mandatory = $true)][UInt32]$C
			)

			# S-1-5-21-<A>-<B>-<C>
			$sid = New-Object byte[] 24
			$sid[0] = 1  # revision
			$sid[1] = 4  # subauth count (21 + 3)
			# IdentifierAuthority (NT authority = 5)
			$sid[2] = 0; $sid[3] = 0; $sid[4] = 0; $sid[5] = 0; $sid[6] = 0; $sid[7] = 5
			[Array]::Copy([BitConverter]::GetBytes([UInt32]21), 0, $sid, 8, 4)
			[Array]::Copy([BitConverter]::GetBytes([UInt32]$A), 0, $sid, 12, 4)
			[Array]::Copy([BitConverter]::GetBytes([UInt32]$B), 0, $sid, 16, 4)
			[Array]::Copy([BitConverter]::GetBytes([UInt32]$C), 0, $sid, 20, 4)
			return ,$sid
		}

		function script:New-EncryptedNtHashBlob {
			param(
				[Parameter(Mandatory = $true)][byte[]]$MasterKey,
				[Parameter(Mandatory = $true)][UInt32]$Rid,
				[Parameter(Mandatory = $true)][byte[]]$NtHash,
				[Parameter(Mandatory = $true)][byte[]]$Salt
			)

			if ($MasterKey.Length -ne 16) { throw "MasterKey must be 16 bytes, got $($MasterKey.Length)." }
			if ($NtHash.Length -ne 16) { throw "NtHash must be 16 bytes, got $($NtHash.Length)." }
			if ($Salt.Length -ne 16) { throw "Salt must be 16 bytes, got $($Salt.Length)." }

			$b0 = [byte]($Rid -band 0xFF)
			$b1 = [byte](($Rid -shr 8) -band 0xFF)
			$b2 = [byte](($Rid -shr 16) -band 0xFF)
			$b3 = [byte](($Rid -shr 24) -band 0xFF)

			function script:New-Key56([byte[]]$Bytes7) {
				[UInt64]$k = 0
				foreach ($b in $Bytes7) {
					$k = ($k -shl 8) -bor [UInt64]$b
				}
				return $k
			}

			$key1_56 = New-Key56 -Bytes7 @($b2, $b1, $b0, $b3, $b2, $b1, $b0)
			$key2_56 = New-Key56 -Bytes7 @($b1, $b0, $b3, $b2, $b1, $b0, $b3)

			$k1 = [Titanis.Crypto.DesPrimitives]::ExpandKey($key1_56)
			$k2 = [Titanis.Crypto.DesPrimitives]::ExpandKey($key2_56)

			[UInt64]$p1 = [BitConverter]::ToUInt64($NtHash, 0)
			[UInt64]$p2 = [BitConverter]::ToUInt64($NtHash, 8)

			[UInt64]$a1 = [Titanis.Crypto.DesPrimitives]::EncryptBlock($k1, $p1)
			[UInt64]$a2 = [Titanis.Crypto.DesPrimitives]::EncryptBlock($k2, $p2)

			$aesPlain = New-Object byte[] 16
			[Array]::Copy([BitConverter]::GetBytes($a1), 0, $aesPlain, 0, 8)
			[Array]::Copy([BitConverter]::GetBytes($a2), 0, $aesPlain, 8, 8)

			$aes = [System.Security.Cryptography.Aes]::Create()
			try {
				$aes.Key = $MasterKey
				$cipher = $aes.EncryptCbc($aesPlain, $Salt)
			} finally {
				$aes.Dispose()
			}

			$blob = New-Object byte[] (24 + $cipher.Length)
			[Array]::Copy([BitConverter]::GetBytes([UInt16]0), 0, $blob, 0, 2)   # key id (unused)
			[Array]::Copy([BitConverter]::GetBytes([UInt16]2), 0, $blob, 2, 2)   # revision
			[Array]::Copy([BitConverter]::GetBytes([UInt16]24), 0, $blob, 4, 2)  # encrypted data offset (unused)
			# bytes 6-7 reserved
			[Array]::Copy($Salt, 0, $blob, 8, 16)
			[Array]::Copy($cipher, 0, $blob, 24, $cipher.Length)
			return ,$blob
		}

		function script:New-SamUserVBytes {
			param(
				[Parameter(Mandatory = $true)][string]$AccountName,
				[Parameter(Mandatory = $true)][byte[]]$EncryptedNtHashBlob
			)

			$accountNameBytes = [System.Text.Encoding]::Unicode.GetBytes($AccountName)
			$attrTableSize = 17 * 12
			$variableSize = $accountNameBytes.Length + $EncryptedNtHashBlob.Length
			$v = New-Object byte[] ($attrTableSize + $variableSize)

			# Attr indexes match Titanis.Msrpc.Msrrp.Cli.SamUserAttrIndex.
			$idxAccountName = 1
			$idxEncryptedNt = 14

			function script:Write-AttrInfo([byte[]]$Bytes, [int]$AttrIndex, [int]$Offset, [int]$Length) {
				$base = $AttrIndex * 12
				[Array]::Copy([BitConverter]::GetBytes([Int32]$Offset), 0, $Bytes, $base + 0, 4)
				[Array]::Copy([BitConverter]::GetBytes([Int32]$Length), 0, $Bytes, $base + 4, 4)
				# extra (ignored)
			}

			Write-AttrInfo -Bytes $v -AttrIndex $idxAccountName -Offset 0 -Length $accountNameBytes.Length
			Write-AttrInfo -Bytes $v -AttrIndex $idxEncryptedNt -Offset $accountNameBytes.Length -Length $EncryptedNtHashBlob.Length

			[Array]::Copy($accountNameBytes, 0, $v, $attrTableSize + 0, $accountNameBytes.Length)
			[Array]::Copy($EncryptedNtHashBlob, 0, $v, $attrTableSize + $accountNameBytes.Length, $EncryptedNtHashBlob.Length)

			return ,$v
		}

		function script:New-FakeSamStore {
			param(
				[Parameter(Mandatory = $true)][byte[]]$SysKey,
				[Parameter(Mandatory = $true)][byte[]]$MasterKey,
				[Parameter(Mandatory = $true)][byte[]]$DomainSidBytes,
				[Parameter(Mandatory = $true)][UInt32]$Rid,
				[Parameter(Mandatory = $true)][byte[]]$SamUserVBytes
			)

			$store = [Titanis.Tbo.Smb2.PowerShell.FakeRegistryStore]::new()

			$lsaBase = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
			$classNames = Get-BootKeyClassNames -BootKey $SysKey
			foreach ($name in @('JD', 'Skew1', 'GBG', 'Data')) {
				$store.AddKey("$lsaBase\\$name", $classNames[$name]) | Out-Null
			}

			$samSalt = [byte[]](1..16)
			$fBytes = New-SamAccountFBytes -SysKey $SysKey -MasterKey $MasterKey -Salt $samSalt
			$store.SetBinaryValue('HKLM\SAM\SAM\Domains\Account', 'F', $fBytes) | Out-Null
			$store.SetBinaryValue('HKLM\SAM\SAM\Domains\Account', 'V', $DomainSidBytes) | Out-Null

			$ridKey = $Rid.ToString('X8')
			$store.SetBinaryValue("HKLM\SAM\SAM\Domains\Account\Users\\$ridKey", 'V', $SamUserVBytes) | Out-Null

			return $store
		}

		$script:repoRoot = Get-TboRepoRoot -Paths @($PSScriptRoot, (Get-Location).Path)
		$script:moduleAvailable = $false
		if ($script:repoRoot) {
			try {
				Import-TboModuleForTests -RepoRoot $script:repoRoot | Out-Null
				if (-not ('Titanis.Crypto.DesPrimitives' -as [type])) {
					$module = Get-Module -Name 'Titanis.TBO.Smb2.PowerShell' -ErrorAction SilentlyContinue
					$candidates = @()
					if ($module -and $module.Path) {
						$candidates += (Join-Path (Split-Path -Parent $module.Path) 'Titanis.Crypto.Des.dll')
					}
					$candidates += (Join-Path $script:repoRoot 'Lib\\Core\\Titanis.Crypto.Des.dll')

					foreach ($candidate in $candidates) {
						if (-not (Test-Path -LiteralPath $candidate)) { continue }
						try {
							[System.Reflection.Assembly]::LoadFrom($candidate) | Out-Null
						} catch {
						}
						if ('Titanis.Crypto.DesPrimitives' -as [type]) { break }
					}
				}
				$script:moduleAvailable = $true
			} catch {
				$script:moduleAvailable = $false
			}
		}

		$script:originalCachePath = $env:TITANIS_TBO_CACHE
	}

	AfterAll {
		if ($null -eq $script:originalCachePath) {
			Remove-Item env:TITANIS_TBO_CACHE -ErrorAction SilentlyContinue
		} else {
			$env:TITANIS_TBO_CACHE = $script:originalCachePath
		}
	}

	It 'ingests local SAM account observations with PrincipalSid (machine SID + RID) when derivable' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$cachePath = Join-Path $TestDrive 'sam_cache.sqlite3'
		$env:TITANIS_TBO_CACHE = $cachePath
		Clear-TBOCache -Confirm:$false

		$rid = [UInt32]500
		$sysKey = [byte[]](0..15)
		$masterKey = [byte[]](16..31)
		$ntHash = New-Object byte[] 16  # all zeros
		$hashSalt = [byte[]](32..47)

		$encBlob = New-EncryptedNtHashBlob -MasterKey $masterKey -Rid $rid -NtHash $ntHash -Salt $hashSalt
		$userV = New-SamUserVBytes -AccountName 'Administrator' -EncryptedNtHashBlob $encBlob

		$domainSid1 = New-DomainSidBytes -A 111 -B 222 -C 333
		$domainSid2 = New-DomainSidBytes -A 444 -B 555 -C 666

		$store1 = New-FakeSamStore -SysKey $sysKey -MasterKey $masterKey -DomainSidBytes $domainSid1 -Rid $rid -SamUserVBytes $userV
		$store2 = New-FakeSamStore -SysKey $sysKey -MasterKey $masterKey -DomainSidBytes $domainSid2 -Rid $rid -SamUserVBytes $userV

		$session1 = $store1.CreateSession()
		$session2 = $store2.CreateSession()

		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRegistrySession { param($serverName, $token)
				switch ($serverName) {
					'host1' { return $session1 }
					'host2' { return $session2 }
					default { throw "Unexpected server name: $serverName" }
				}
			}

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Get-TBORegSamHashes -ServerName host1 -Cache | Out-Null
			Get-TBORegSamHashes -ServerName host2 -Cache | Out-Null
		}

		$info = Get-TBOCacheInfo
		$info.MachineCount | Should -Be 2
		$info.PrincipalCount | Should -Be 2
		$info.CredentialCount | Should -Be 1
		$info.ObservationCount | Should -Be 2

		$conn = [Microsoft.Data.Sqlite.SqliteConnection]::new("Data Source=$cachePath;Mode=ReadWrite;Pooling=False")
		$conn.Open()
		try {
			$cmd = $conn.CreateCommand()
			$cmd.CommandText = "SELECT sid FROM principals WHERE sid IS NOT NULL ORDER BY sid;"
			$reader = $cmd.ExecuteReader()
			$sids = @()
			while ($reader.Read()) {
				$sids += $reader.GetString(0)
			}
			$reader.Dispose()

			$sids.Count | Should -Be 2
			$sids | Should -Contain 'S-1-5-21-111-222-333-500'
			$sids | Should -Contain 'S-1-5-21-444-555-666-500'
		} finally {
			$conn.Dispose()
		}
	}
}
