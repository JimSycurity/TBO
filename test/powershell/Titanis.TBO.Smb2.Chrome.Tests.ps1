Set-StrictMode -Version Latest

BeforeAll {
	$script:testHarnessPath = Join-Path $PSScriptRoot 'TboTestHarness.ps1'
	if (Test-Path -LiteralPath $script:testHarnessPath) {
		. $script:testHarnessPath
	}

	$script:repoRoot = $null
	$script:moduleAvailable = $false

	if (Get-Command -Name Get-TboRepoRoot -ErrorAction SilentlyContinue) {
		$script:repoRoot = Get-TboRepoRoot -Paths @($PSScriptRoot, (Get-Location).Path)
	}

	if ($script:repoRoot) {
		try {
			Import-TboModuleForTests -RepoRoot $script:repoRoot | Out-Null
			$script:moduleAvailable = $true
		} catch {
			$script:moduleAvailable = $false
		}
	}
}

Describe 'Chrome helpers (fake SMB file system)' {
	It 'EnumerateProfileDirectories returns known Chrome profiles in stable order' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for fake SMB tests.'
			return
		}

		if (-not ('Titanis.Tbo.Smb2.PowerShell.FakeSmbFileSystem' -as [type])) {
			Set-ItResult -Skipped -Because 'Fake SMB file system not found; rebuild the module to include it.'
			return
		}

		$fake = [Titanis.Tbo.Smb2.PowerShell.FakeSmbFileSystem]::new()
		$fake.AddDirectory("\\server\C$\Users") | Out-Null
		$fake.AddDirectory("\\server\C$\Users\jsmith") | Out-Null
		$fake.AddDirectory("\\server\C$\Users\jsmith\AppData\Local\Google\Chrome\User Data") | Out-Null

		# Profiles
		$fake.AddDirectory("\\server\C$\Users\jsmith\AppData\Local\Google\Chrome\User Data\Profile 10") | Out-Null
		$fake.AddDirectory("\\server\C$\Users\jsmith\AppData\Local\Google\Chrome\User Data\Default") | Out-Null
		$fake.AddDirectory("\\server\C$\Users\jsmith\AppData\Local\Google\Chrome\User Data\Profile 2") | Out-Null
		$fake.AddDirectory("\\server\C$\Users\jsmith\AppData\Local\Google\Chrome\User Data\Guest Profile") | Out-Null
		$fake.AddDirectory("\\server\C$\Users\jsmith\AppData\Local\Google\Chrome\User Data\System Profile") | Out-Null

		# Noise
		$fake.AddDirectory("\\server\C$\Users\jsmith\AppData\Local\Google\Chrome\User Data\Crashpad") | Out-Null

		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot
		$mock.FileSystem = $fake

		$asm = [Titanis.Tbo.Smb2.PowerShell.FakeSmbFileSystem].Assembly
		$chromeHelpersType = $asm.GetType('Titanis.Tbo.Smb2.PowerShell.ChromeHelpers', $false)
		$chromeHelpersType | Should -Not -BeNullOrEmpty

			$flags = [System.Reflection.BindingFlags]::Static -bor [System.Reflection.BindingFlags]::NonPublic
			$method = $chromeHelpersType.GetMethods($flags) | Where-Object { $_.Name -eq 'EnumerateProfileDirectories' -and $_.GetParameters().Count -eq 9 } | Select-Object -First 1
			$method | Should -Not -BeNullOrEmpty

			$profiles = @($method.Invoke($null, @(
				$mock,
				'server',
				'C$',
				'jsmith',
				'Chrome',
				$null,
				$null,
				$null,
				[System.Threading.CancellationToken]::None
			)))

		$profiles | Should -Be @(
			'Default',
			'Profile 2',
			'Profile 10',
			'Guest Profile',
			'System Profile'
		)
	}

	It 'EnumerateProfileDirectories returns empty when Chrome User Data root is missing' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for fake SMB tests.'
			return
		}

		if (-not ('Titanis.Tbo.Smb2.PowerShell.FakeSmbFileSystem' -as [type])) {
			Set-ItResult -Skipped -Because 'Fake SMB file system not found; rebuild the module to include it.'
			return
		}

		$fake = [Titanis.Tbo.Smb2.PowerShell.FakeSmbFileSystem]::new()
		$fake.AddDirectory("\\server\C$\Users") | Out-Null
		$fake.AddDirectory("\\server\C$\Users\jsmith") | Out-Null

		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot
		$mock.FileSystem = $fake

		$asm = [Titanis.Tbo.Smb2.PowerShell.FakeSmbFileSystem].Assembly
		$chromeHelpersType = $asm.GetType('Titanis.Tbo.Smb2.PowerShell.ChromeHelpers', $false)
		$chromeHelpersType | Should -Not -BeNullOrEmpty

		$flags = [System.Reflection.BindingFlags]::Static -bor [System.Reflection.BindingFlags]::NonPublic
		$method = $chromeHelpersType.GetMethods($flags) | Where-Object { $_.Name -eq 'EnumerateProfileDirectories' -and $_.GetParameters().Count -eq 9 } | Select-Object -First 1
		$method | Should -Not -BeNullOrEmpty

		$profiles = @($method.Invoke($null, @(
			$mock,
			'server',
			'C$',
			'jsmith',
			'Chrome',
			$null,
			$null,
			$null,
			[System.Threading.CancellationToken]::None
		)))

		$profiles | Should -Be @()
	}

	It 'EnumerateProfileDirectories respects -Browser path mapping' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for fake SMB tests.'
			return
		}

		if (-not ('Titanis.Tbo.Smb2.PowerShell.FakeSmbFileSystem' -as [type])) {
			Set-ItResult -Skipped -Because 'Fake SMB file system not found; rebuild the module to include it.'
			return
		}

		$fake = [Titanis.Tbo.Smb2.PowerShell.FakeSmbFileSystem]::new()
		$fake.AddDirectory("\\server\C$\Users") | Out-Null
		$fake.AddDirectory("\\server\C$\Users\jsmith") | Out-Null

		# Edge user data root only (no Chrome root).
		$fake.AddDirectory("\\server\C$\Users\jsmith\AppData\Local\Microsoft\Edge\User Data") | Out-Null
		$fake.AddDirectory("\\server\C$\Users\jsmith\AppData\Local\Microsoft\Edge\User Data\Default") | Out-Null
		$fake.AddDirectory("\\server\C$\Users\jsmith\AppData\Local\Microsoft\Edge\User Data\Profile 1") | Out-Null

		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot
		$mock.FileSystem = $fake

		$asm = [Titanis.Tbo.Smb2.PowerShell.FakeSmbFileSystem].Assembly
		$chromeHelpersType = $asm.GetType('Titanis.Tbo.Smb2.PowerShell.ChromeHelpers', $false)
		$chromeHelpersType | Should -Not -BeNullOrEmpty

		$flags = [System.Reflection.BindingFlags]::Static -bor [System.Reflection.BindingFlags]::NonPublic
		$method = $chromeHelpersType.GetMethods($flags) | Where-Object { $_.Name -eq 'EnumerateProfileDirectories' -and $_.GetParameters().Count -eq 9 } | Select-Object -First 1
		$method | Should -Not -BeNullOrEmpty

		$edgeProfiles = @($method.Invoke($null, @(
			$mock,
			'server',
			'C$',
			'jsmith',
			'Edge',
			$null,
			$null,
			$null,
			[System.Threading.CancellationToken]::None
		)))

		$edgeProfiles | Should -Be @('Default', 'Profile 1')

		$chromeProfiles = @($method.Invoke($null, @(
			$mock,
			'server',
			'C$',
			'jsmith',
			'Chrome',
			$null,
			$null,
			$null,
			[System.Threading.CancellationToken]::None
		)))

		$chromeProfiles | Should -Be @()
	}
}

Describe 'Chrome Local State parsing' {
	It 'TryParseEncryptedStateKey parses os_crypt.encrypted_key from Local State JSON' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for Local State parsing tests.'
			return
		}

		if (-not ('Titanis.Tbo.Smb2.PowerShell.FakeSmbFileSystem' -as [type])) {
			Set-ItResult -Skipped -Because 'Fake SMB file system not found; rebuild the module to include it.'
			return
		}

		$asm = [Titanis.Tbo.Smb2.PowerShell.FakeSmbFileSystem].Assembly
		$cacheType = $asm.GetType('Titanis.Tbo.Smb2.PowerShell.ChromeStateKeyCache', $false)
		$cacheType | Should -Not -BeNullOrEmpty

		$flags = [System.Reflection.BindingFlags]::Static -bor [System.Reflection.BindingFlags]::NonPublic
		$method = $cacheType.GetMethods($flags) | Where-Object { $_.Name -eq 'TryParseEncryptedStateKey' } | Select-Object -First 1
		$method | Should -Not -BeNullOrEmpty

		$payload = [byte[]](0x44, 0x50, 0x41, 0x50, 0x49, 0x01, 0x02, 0x03) # "DPAPI" + 0x01 0x02 0x03
		$base64 = [Convert]::ToBase64String($payload)
		$json = "{`"os_crypt`": {`"encrypted_key`": `"$base64`"}}"
		$localStateBytes = [System.Text.Encoding]::UTF8.GetBytes($json)

		$args = @($localStateBytes, [byte[]]::new(0), $null)
		$ok = $method.Invoke($null, $args)
		$ok | Should -BeTrue
		$args[1] | Should -Be $payload
		$args[2] | Should -BeNullOrEmpty
	}

	It 'TryStripDpapiHeader strips the DPAPI prefix from Local State encrypted_key bytes' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for Local State parsing tests.'
			return
		}

		if (-not ('Titanis.Tbo.Smb2.PowerShell.FakeSmbFileSystem' -as [type])) {
			Set-ItResult -Skipped -Because 'Fake SMB file system not found; rebuild the module to include it.'
			return
		}

		$asm = [Titanis.Tbo.Smb2.PowerShell.FakeSmbFileSystem].Assembly
		$chromeHelpersType = $asm.GetType('Titanis.Tbo.Smb2.PowerShell.ChromeHelpers', $false)
		$chromeHelpersType | Should -Not -BeNullOrEmpty

		$flags = [System.Reflection.BindingFlags]::Static -bor [System.Reflection.BindingFlags]::NonPublic
		$method = $chromeHelpersType.GetMethods($flags) | Where-Object { $_.Name -eq 'TryStripDpapiHeader' } | Select-Object -First 1
		$method | Should -Not -BeNullOrEmpty

		$payload = [byte[]](0x44, 0x50, 0x41, 0x50, 0x49, 0x01, 0x02, 0x03) # "DPAPI" + 0x01 0x02 0x03
		$args = @($payload, [byte[]]::new(0), $null)
		$ok = $method.Invoke($null, $args)
		$ok | Should -BeTrue
		$args[1] | Should -Be ([byte[]](0x01, 0x02, 0x03))
		$args[2] | Should -BeNullOrEmpty

		$badPayload = [System.Text.Encoding]::UTF8.GetBytes('NOPE')
		$argsBad = @($badPayload, [byte[]]::new(0), $null)
		$okBad = $method.Invoke($null, $argsBad)
		$okBad | Should -BeFalse
		$argsBad[2] | Should -Be 'DPAPI header missing.'
	}
}

Describe 'Chrome DPAPI parsing' {
	It 'HasV10OrV11Header also recognizes newer Chromium AES headers such as v20' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for Chrome header parsing tests.'
			return
		}

		if (-not ('Titanis.Tbo.Smb2.PowerShell.FakeSmbFileSystem' -as [type])) {
			Set-ItResult -Skipped -Because 'Fake SMB file system not found; rebuild the module to include it.'
			return
		}

		$asm = [Titanis.Tbo.Smb2.PowerShell.FakeSmbFileSystem].Assembly
		$chromeCryptoType = $asm.GetType('Titanis.Tbo.Smb2.PowerShell.ChromeCrypto', $false)
		$chromeCryptoType | Should -Not -BeNullOrEmpty

		$flags = [System.Reflection.BindingFlags]::Static -bor [System.Reflection.BindingFlags]::NonPublic
		$method = $chromeCryptoType.GetMethods($flags) | Where-Object {
			$_.Name -eq 'HasV10OrV11Header' -and $_.GetParameters().Count -eq 2
		} | Select-Object -First 1
		$method | Should -Not -BeNullOrEmpty

		$v20Payload = [System.Text.Encoding]::ASCII.GetBytes('v20abc')
		$args = @($v20Payload, '')
		$ok = $method.Invoke($null, $args)
		$ok | Should -BeTrue
		$args[1] | Should -Be 'v20'

		$badPayload = [System.Text.Encoding]::ASCII.GetBytes('x20abc')
		$argsBad = @($badPayload, '')
		$okBad = $method.Invoke($null, $argsBad)
		$okBad | Should -BeFalse
	}

	It 'TryDecryptDpapi locates DPAPI blob magic when payload has a non-DPAPI prefix' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for Chrome DPAPI parsing tests.'
			return
		}

		if (-not ('Titanis.Tbo.Smb2.PowerShell.FakeSmbFileSystem' -as [type])) {
			Set-ItResult -Skipped -Because 'Fake SMB file system not found; rebuild the module to include it.'
			return
		}

		$asm = [Titanis.Tbo.Smb2.PowerShell.FakeSmbFileSystem].Assembly
		$chromeCryptoType = $asm.GetType('Titanis.Tbo.Smb2.PowerShell.ChromeCrypto', $false)
		$chromeCryptoType | Should -Not -BeNullOrEmpty

		$flags = [System.Reflection.BindingFlags]::Static -bor [System.Reflection.BindingFlags]::NonPublic
		$method = $chromeCryptoType.GetMethods($flags) | Where-Object {
			$_.Name -eq 'TryDecryptDpapi' -and $_.GetParameters().Count -eq 7
		} | Select-Object -First 1
		$method | Should -Not -BeNullOrEmpty

		$masterGuid = [Guid]::Parse('12345678-1234-1234-1234-1234567890ab')
		$magic = [byte[]](0x01,0x00,0x00,0x00,0xD0,0x8C,0x9D,0xDF,0x01,0x15,0xD1,0x11,0x8C,0x7A,0x00,0xC0,0x4F,0xC2,0x97,0xEB)

		# Minimal parseable DPAPI blob with empty variable-length fields.
		$blobBytes = New-Object System.Collections.Generic.List[byte]
		$blobBytes.AddRange($magic)
		$blobBytes.AddRange([BitConverter]::GetBytes([uint32]1)) # MasterKeyVersion
		$blobBytes.AddRange($masterGuid.ToByteArray())
		$blobBytes.AddRange([BitConverter]::GetBytes([uint32]0)) # Flags
		$blobBytes.AddRange([BitConverter]::GetBytes([uint32]0)) # DescriptionLen
		$blobBytes.AddRange([BitConverter]::GetBytes([uint32]0x6610)) # CryptAlgorithm
		$blobBytes.AddRange([BitConverter]::GetBytes([uint32]0x20)) # CryptAlgorithmLength
		$blobBytes.AddRange([BitConverter]::GetBytes([uint32]0)) # SaltLen
		$blobBytes.AddRange([BitConverter]::GetBytes([uint32]0)) # HmacKeyLen
		$blobBytes.AddRange([BitConverter]::GetBytes([uint32]0x800e)) # HashAlgorithm
		$blobBytes.AddRange([BitConverter]::GetBytes([uint32]0)) # HashAlgorithmLength
		$blobBytes.AddRange([BitConverter]::GetBytes([uint32]0)) # HmacLen
		$blobBytes.AddRange([BitConverter]::GetBytes([uint32]0)) # DataLen
		$blobBytes.AddRange([BitConverter]::GetBytes([uint32]0)) # SignLen

		$prefixed = New-Object System.Collections.Generic.List[byte]
		$prefixed.AddRange([byte[]](0xAA,0xBB,0xCC,0xDD))
		$prefixed.AddRange($blobBytes.ToArray())
		$prefixedPayload = $prefixed.ToArray()
		$masterKeySet = [System.Collections.Generic.Dictionary[Guid, byte[]]]::new()
		$args = @($prefixedPayload, $masterKeySet, $null, $null, $null, $false, $null)

		$ok = $method.Invoke($null, $args)
		$ok | Should -BeFalse
		$args[4] | Should -Be $masterGuid.ToString()
		$args[6] | Should -Match 'Master key .* was not found'
	}
}
