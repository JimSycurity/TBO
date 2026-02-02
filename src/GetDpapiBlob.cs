using System;
using System.IO;
using System.Management.Automation;
using System.Text;
using System.Threading;
using Titanis;
using Titanis.Msrpc.Msrrp;
using Titanis.Net;
using Titanis.Smb2;
using Winterop = Titanis.Winterop;
using Smb2AccessRights = Titanis.Smb2.Smb2FileAccessRights;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboDpapiBlobDecryptionInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string Source { get; init; } = string.Empty;
		public string? Path { get; init; }
		public string? ValueName { get; init; }
		public int Offset { get; init; }
		public string? CredentialGuid { get; init; }
		public string? MasterKeyGuid { get; init; }
		public uint Flags { get; init; }
		public string? Description { get; init; }
		public uint CryptAlgorithmId { get; init; }
		public string? CryptAlgorithm { get; init; }
		public uint HashAlgorithmId { get; init; }
		public string? HashAlgorithm { get; init; }
		public string? Cleartext { get; init; }
		public string? CleartextHex { get; init; }
		public byte[]? CleartextBytes { get; init; }
		public bool HmacValidated { get; init; }
		public string? FailureReason { get; init; }
	}

	[Cmdlet(VerbsCommon.Get, "TBODpapiBlob", DefaultParameterSetName = FileParameterSet)]
	[OutputType(typeof(TboDpapiBlobDecryptionInfo))]
	public sealed class GetTBODpapiBlob : TboRegCmdlet
	{
		private const string InputObjectParameterSet = "InputObject";
		private const string FileParameterSet = "File";
		private const string RegistryParameterSet = "Registry";
		private const string BytesParameterSet = "Bytes";
		private const string HexParameterSet = "Hex";
		private const string Base64ParameterSet = "Base64";

		[Parameter(Mandatory = true, ValueFromPipeline = true, ParameterSetName = InputObjectParameterSet)]
		public TboDpapiBlobInfo? InputObject { get; set; }

		[Parameter(Mandatory = true, Position = 1, ParameterSetName = FileParameterSet, ValueFromPipelineByPropertyName = true)]
		public string Path { get; set; } = string.Empty;

		[Parameter(Mandatory = true, Position = 1, ParameterSetName = RegistryParameterSet, ValueFromPipelineByPropertyName = true)]
		[Alias("KeyPath")]
		public string RegistryPath { get; set; } = string.Empty;

		[Parameter(Mandatory = true, Position = 2, ParameterSetName = RegistryParameterSet, ValueFromPipelineByPropertyName = true)]
		public string ValueName { get; set; } = string.Empty;

		[Parameter(Mandatory = true, ParameterSetName = BytesParameterSet)]
		public byte[]? BlobBytes { get; set; }

		[Parameter(Mandatory = true, ParameterSetName = HexParameterSet)]
		public string? BlobHex { get; set; }

		[Parameter(Mandatory = true, ParameterSetName = Base64ParameterSet)]
		public string? BlobBase64 { get; set; }

		[Parameter(ValueFromPipelineByPropertyName = true)]
		[Alias("MatchOffset")]
		public int Offset { get; set; }

		[Parameter(ValueFromPipelineByPropertyName = true)]
		public string? MasterKey { get; set; }

		[Parameter]
		public byte[]? MasterKeyBytes { get; set; }

		[Parameter]
		public string? Entropy { get; set; }

		[Parameter]
		public byte[]? EntropyBytes { get; set; }

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			var masterKey = ResolveMasterKey();
			if (masterKey == null || masterKey.Length == 0)
				throw new ArgumentException("MasterKey must be provided (hex) or MasterKeyBytes must be set.", nameof(this.MasterKey));

			var entropy = ResolveEntropy();

			DpapiBlobInput input;
			try
			{
				input = ResolveInput(smb, cancellationToken);
			}
			catch (Exception ex)
			{
				this.WriteObject(new TboDpapiBlobDecryptionInfo
				{
					ServerName = this.ServerName,
					Source = this.ParameterSetName,
					FailureReason = ex.Message
				});
				return;
			}

			DpapiBlob blob;
			try
			{
				blob = DpapiBlob.Parse(input.Data, input.Offset);
			}
			catch (Exception ex)
			{
				this.WriteObject(new TboDpapiBlobDecryptionInfo
				{
					ServerName = this.ServerName,
					Source = input.Source,
					Path = input.Path,
					ValueName = input.ValueName,
					Offset = input.Offset,
					FailureReason = $"Failed to parse DPAPI blob: {ex.Message}"
				});
				return;
			}

			var decryptResult = DpapiBlobCrypto.Decrypt(blob, masterKey, entropy);
			var cleartextBytes = decryptResult.Cleartext;
			var cleartextText = cleartextBytes != null ? TryDecodeCleartext(cleartextBytes) : null;

			this.WriteObject(new TboDpapiBlobDecryptionInfo
			{
				ServerName = this.ServerName,
				Source = input.Source,
				Path = input.Path,
				ValueName = input.ValueName,
				Offset = input.Offset,
				CredentialGuid = blob.GuidCredential.ToString(),
				MasterKeyGuid = blob.GuidMasterKey.ToString(),
				Flags = blob.Flags,
				Description = blob.Description,
				CryptAlgorithmId = blob.CryptAlgorithm,
				CryptAlgorithm = ResolveCryptAlgorithmName(blob.CryptAlgorithm, blob.CryptAlgorithmLength),
				HashAlgorithmId = blob.HashAlgorithm,
				HashAlgorithm = ResolveHashAlgorithmName(blob.HashAlgorithm, blob.HashAlgorithmLength),
				Cleartext = cleartextText,
				CleartextHex = cleartextBytes?.ToHexString(),
				CleartextBytes = cleartextBytes,
				HmacValidated = decryptResult.HmacValidated,
				FailureReason = decryptResult.FailureReason
			});
		}

		private DpapiBlobInput ResolveInput(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			if (this.ParameterSetName == InputObjectParameterSet)
			{
				if (this.InputObject == null)
					throw new ArgumentException("InputObject must be provided.", nameof(this.InputObject));

				var offset = this.Offset != 0 ? this.Offset : this.InputObject.MatchOffset;
				if (this.InputObject.Source.Equals("Registry", StringComparison.OrdinalIgnoreCase))
				{
					if (string.IsNullOrWhiteSpace(this.InputObject.ValueName))
						throw new ArgumentException("Registry blob input is missing ValueName.");
					return ReadRegistryInput(smb, this.InputObject.Path, this.InputObject.ValueName, offset, cancellationToken);
				}

				return ReadFileInput(smb, this.InputObject.Path, offset, cancellationToken);
			}

			if (this.ParameterSetName == RegistryParameterSet)
			{
				return ReadRegistryInput(smb, this.RegistryPath, this.ValueName, this.Offset, cancellationToken);
			}

			if (this.ParameterSetName == FileParameterSet)
			{
				return ReadFileInput(smb, this.Path, this.Offset, cancellationToken);
			}

			if (this.ParameterSetName == BytesParameterSet)
			{
				if (this.BlobBytes == null || this.BlobBytes.Length == 0)
					throw new ArgumentException("BlobBytes must be provided.", nameof(this.BlobBytes));
				return new DpapiBlobInput
				{
					Data = this.BlobBytes,
					Offset = this.Offset,
					Source = "Bytes"
				};
			}

			if (this.ParameterSetName == HexParameterSet)
			{
				if (string.IsNullOrWhiteSpace(this.BlobHex))
					throw new ArgumentException("BlobHex must be provided.", nameof(this.BlobHex));
				return new DpapiBlobInput
				{
					Data = BinaryHelper.ParseHexString(this.BlobHex.AsSpan()),
					Offset = this.Offset,
					Source = "Hex"
				};
			}

			if (this.ParameterSetName == Base64ParameterSet)
			{
				if (string.IsNullOrWhiteSpace(this.BlobBase64))
					throw new ArgumentException("BlobBase64 must be provided.", nameof(this.BlobBase64));
				return new DpapiBlobInput
				{
					Data = Convert.FromBase64String(this.BlobBase64),
					Offset = this.Offset,
					Source = "Base64"
				};
			}

			throw new InvalidOperationException("Unsupported parameter set.");
		}

		private DpapiBlobInput ReadFileInput(ISmbProviderInfo smb, string path, int offset, CancellationToken cancellationToken)
		{
			if (string.IsNullOrWhiteSpace(path))
				throw new ArgumentException("Path must be provided.", nameof(this.Path));

			var uncPath = ResolveToUncPath(path, nameof(this.Path));
			if (string.IsNullOrEmpty(uncPath.ShareName))
				throw new ArgumentException($"Path must include a share name: {uncPath}", nameof(this.Path));

			if (!string.IsNullOrEmpty(uncPath.ServerName)
				&& !uncPath.ServerName.Equals(this.ServerName, StringComparison.OrdinalIgnoreCase))
				throw new ArgumentException($"ServerName '{this.ServerName}' does not match UNC host '{uncPath.ServerName}'.", nameof(this.ServerName));

			var bytes = ReadFileBytes(smb, uncPath, cancellationToken);
			return new DpapiBlobInput
			{
				Source = "File",
				Path = uncPath.ToString(),
				Offset = offset,
				Data = bytes
			};
		}

		private DpapiBlobInput ReadRegistryInput(ISmbProviderInfo smb, string registryPath, string valueName, int offset, CancellationToken cancellationToken)
		{
			if (string.IsNullOrWhiteSpace(registryPath))
				throw new ArgumentException("RegistryPath must be provided.", nameof(this.RegistryPath));
			if (string.IsNullOrWhiteSpace(valueName))
				throw new ArgumentException("ValueName must be provided.", nameof(this.ValueName));

			var parsedPath = ParseRegistryPath(registryPath, nameof(this.RegistryPath));
			var valueInfo = ExecuteRegistryOperation(smb, cancellationToken, session =>
			{
				using var key = OpenRegistryKey(session.Client, parsedPath, RegistryAccessRights.QueryValue, cancellationToken);
				return key.GetValue(valueName, cancellationToken).GetAwaiter().GetResult();
			});

			if (valueInfo.Bytes == null || valueInfo.Bytes.Length == 0)
				throw new InvalidDataException($"Registry value '{registryPath}\\{valueName}' did not contain binary data.");

			return new DpapiBlobInput
			{
				Source = "Registry",
				Path = parsedPath.KeyPath,
				ValueName = valueName,
				Offset = offset,
				Data = valueInfo.Bytes
			};
		}

		private static byte[] ReadFileBytes(ISmbProviderInfo smb, UncPath path, CancellationToken cancellationToken)
		{
			using var file = OpenFileRead(smb.SmbClient, path, cancellationToken);
			using var stream = file.GetStream(false);
			using var memory = new MemoryStream();
			stream.CopyTo(memory);
			return memory.ToArray();
		}

		private static Smb2OpenFile OpenFileRead(Smb2Client client, UncPath path, CancellationToken cancellationToken)
		{
			return (Smb2OpenFile)client.CreateFileAsync(path, new Smb2CreateInfo
			{
				CreateDisposition = Smb2CreateDisposition.Open,
				DesiredAccess = (uint)Smb2AccessRights.DefaultOpenReadAccess,
				ShareAccess = Smb2ShareAccess.Read,
				ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
				CreateOptions = Smb2FileCreateOptions.NonDirectory
					| Smb2FileCreateOptions.SynchronousIoNonalert
					| Smb2FileCreateOptions.OpenForBackupIntent,
				FileAttributes = Winterop.FileAttributes.Normal,
				RequestMaximalAccess = true
			}, FileAccess.Read, cancellationToken).GetAwaiter().GetResult();
		}

		private static string ResolveCryptAlgorithmName(uint algoId, uint algoLen)
		{
			return algoId switch
			{
				0x6601 => "DES",
				0x6603 => "DES3",
				0x660e => "AES-128",
				0x660f => "AES-192",
				0x6610 => "AES-256",
				0x6611 => algoLen switch
				{
					128 => "AES-128",
					192 => "AES-192",
					256 => "AES-256",
					_ => "AES"
				},
				_ => $"0x{algoId:x}"
			};
		}

		private static string ResolveHashAlgorithmName(uint algoId, uint algoLen)
		{
			if (algoId == 0x8009)
			{
				if (algoLen >= 512)
					return "SHA512";
				if (algoLen >= 384)
					return "SHA384";
				if (algoLen >= 256)
					return "SHA256";
				return "SHA1";
			}

			return algoId switch
			{
				0x8003 => "MD5",
				0x8004 => "SHA1",
				0x800c => "SHA256",
				0x800d => "SHA384",
				0x800e => "SHA512",
				_ => $"0x{algoId:x}"
			};
		}

		private byte[]? ResolveMasterKey()
		{
			if (this.MasterKeyBytes != null && this.MasterKeyBytes.Length > 0)
				return this.MasterKeyBytes;
			if (!string.IsNullOrWhiteSpace(this.MasterKey))
				return BinaryHelper.ParseHexString(this.MasterKey.AsSpan());
			return null;
		}

		private byte[]? ResolveEntropy()
		{
			if (this.EntropyBytes != null && this.EntropyBytes.Length > 0)
				return this.EntropyBytes;
			if (!string.IsNullOrWhiteSpace(this.Entropy))
				return BinaryHelper.ParseHexString(this.Entropy.AsSpan());
			return null;
		}

		private static string? TryDecodeCleartext(byte[] payload)
		{
			if (payload.Length == 0)
				return null;

			if (payload.Length % 2 == 0)
			{
				try
				{
					var str = Encoding.Unicode.GetString(payload).TrimEnd('\0');
					if (IsLikelyText(str))
						return str;
				}
				catch
				{
				}
			}

			try
			{
				var str = Encoding.UTF8.GetString(payload).TrimEnd('\0');
				if (IsLikelyText(str))
					return str;
			}
			catch
			{
			}

			return null;
		}

		private static bool IsLikelyText(string? text)
		{
			if (string.IsNullOrWhiteSpace(text))
				return false;

			int asciiPrintable = 0;
			int controlCount = 0;
			int length = text.Length;

			for (int i = 0; i < length; i++)
			{
				char c = text[i];
				if (c == '\uFFFD')
					return false;
				if (char.IsControl(c) && c != '\r' && c != '\n' && c != '\t')
					controlCount++;
				if (c >= ' ' && c <= '~')
					asciiPrintable++;
			}

			if (controlCount > 0 || asciiPrintable == 0)
				return false;

			double asciiRatio = (double)asciiPrintable / length;
			return asciiRatio >= 0.6;
		}

		private UncPath ResolveToUncPath(string path, string paramName)
		{
			if (string.IsNullOrWhiteSpace(path))
				throw new ArgumentException("Path must be provided.", paramName);

			if (UncPath.TryParse(path, out var uncPath) && uncPath != null)
				return uncPath;

			ProviderInfo? providerInfo;
			PSDriveInfo? driveInfo;
			string providerPath;
			try
			{
				providerPath = this.SessionState.Path.GetUnresolvedProviderPathFromPSPath(path, out providerInfo, out driveInfo);
			}
			catch (Exception ex)
			{
				throw new ArgumentException($"Path could not be resolved: {path}", paramName, ex);
			}

			if (providerInfo == null || !providerInfo.Name.Equals(SmbProvider.ProviderName, StringComparison.OrdinalIgnoreCase))
				throw new ArgumentException($"Path must be a UNC path or a {SmbProvider.ProviderName} PSDrive path: {path}", paramName);

			if (UncPath.TryParse(providerPath, out var resolvedUnc) && resolvedUnc != null)
				return resolvedUnc;

			throw new ArgumentException($"Resolved provider path is not a UNC path: {providerPath}", paramName);
		}

		private sealed class DpapiBlobInput
		{
			public string Source { get; init; } = string.Empty;
			public string? Path { get; init; }
			public string? ValueName { get; init; }
			public int Offset { get; init; }
			public byte[] Data { get; init; } = Array.Empty<byte>();
		}
	}
}
