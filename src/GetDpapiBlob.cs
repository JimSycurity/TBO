using System;
using System.IO;
using System.Management.Automation;
using System.Threading;
using Titanis;
using Titanis.Msrpc.Msrrp;
using Titanis.Net;

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
			var cleartextText = cleartextBytes != null ? DpapiHelpers.TryDecodeCleartext(cleartextBytes) : null;

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
				CryptAlgorithm = DpapiBlobCrypto.ResolveCipherAlgorithmName(blob.CryptAlgorithm, blob.CryptAlgorithmLength),
				HashAlgorithmId = blob.HashAlgorithm,
				HashAlgorithm = DpapiBlobCrypto.ResolveHashAlgorithmName(blob.HashAlgorithm, blob.HashAlgorithmLength),
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

			var bytes = DpapiHelpers.ReadFileBytes(smb, uncPath, cancellationToken);
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
