using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Threading;
using Titanis.Net;
using Titanis.Smb2;
using Titanis.Winterop;
using Titanis.Winterop.Security;
using Winterop = Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	[Flags]
	public enum CredManScope
	{
		None = 0,
		User = 1,
		Machine = 2,
		All = User | Machine
	}

	public sealed class TboCredManFileInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string Scope { get; init; } = string.Empty;
		public string? UserName { get; init; }
		public string? UserSid { get; init; }
		public string? ProfilePath { get; init; }
		public string Container { get; init; } = string.Empty;
		public string? VaultGuid { get; init; }
		public string FileName { get; init; } = string.Empty;
		public string Path { get; init; } = string.Empty;
		public ulong? FileSize { get; init; }
		public DateTime? FileCreationTime { get; init; }
		public DateTime? FileLastWriteTime { get; init; }
		public DateTime? FileLastChangeTime { get; init; }
		public bool IsSystemProfile { get; init; }
	}

	public sealed class TboCredManEntryInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string Scope { get; init; } = string.Empty;
		public string? UserName { get; init; }
		public string? UserSid { get; init; }
		public string? ProfilePath { get; init; }
		public string Container { get; init; } = string.Empty;
		public string? VaultGuid { get; init; }
		public string SourcePath { get; init; } = string.Empty;
		public ulong? FileSize { get; init; }
		public DateTime? FileCreationTime { get; init; }
		public DateTime? FileLastWriteTime { get; init; }
		public DateTime? FileLastChangeTime { get; init; }
		public int? DpapiBlobOffset { get; init; }
		public int BytesScanned { get; init; }
		public byte[]? RawBytes { get; init; }
		public bool HasDpapiBlob => this.DpapiBlobOffset.HasValue;
	}

	[Cmdlet(VerbsCommon.Get, "TBOCredManFiles")]
	[OutputType(typeof(TboCredManFileInfo))]
	public sealed class GetTBOCredManFiles : SmbCmdlet
	{
		[Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true)]
		public string ServerName { get; set; } = string.Empty;

		[Parameter]
		public CredManScope Scope { get; set; } = CredManScope.All;

		[Parameter]
		public string ShareName { get; set; } = CredManLocator.DefaultShareName;

		[Parameter]
		public string[]? UserName { get; set; }

		[Parameter]
		public bool IncludeSystemProfiles { get; set; } = true;

		private CancellationTokenSource? _cancelSource;

		protected override void ProcessRecord(ISmbProviderInfo smb)
		{
			this._cancelSource ??= new CancellationTokenSource();
			var cancellationToken = this._cancelSource.Token;

			var serverName = NormalizeServerName(this.ServerName);
			if (string.IsNullOrWhiteSpace(serverName))
				throw new ArgumentException("ServerName must be provided.", nameof(this.ServerName));

			var shareName = NormalizeShareName(this.ShareName);
			if (string.IsNullOrWhiteSpace(shareName))
				throw new ArgumentException("ShareName must be provided.", nameof(this.ShareName));

			var userFilters = BuildUserFilters(this.UserName);

			var results = CredManLocator.Enumerate(
				smb,
				serverName,
				shareName,
				this.Scope,
				userFilters,
				this.IncludeSystemProfiles,
				message => this.WriteWarning(message),
				message => this.WriteVerbose(message),
				cancellationToken);

			foreach (var entry in results)
			{
				this.WriteObject(entry);
			}
		}

		protected override void StopProcessing()
		{
			this._cancelSource?.Cancel();
			base.StopProcessing();
		}

		private static string NormalizeServerName(string? serverName)
		{
			return string.IsNullOrWhiteSpace(serverName)
				? string.Empty
				: serverName.TrimStart('\\');
		}

		private static string NormalizeShareName(string? shareName)
		{
			if (string.IsNullOrWhiteSpace(shareName))
				return string.Empty;

			var trimmed = shareName.Trim();
			trimmed = trimmed.Trim('\\');
			return trimmed;
		}

		private static IReadOnlyList<WildcardPattern> BuildUserFilters(string[]? filters)
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
	}

	[Cmdlet(VerbsCommon.Get, "TBOCredManEntry", DefaultParameterSetName = PathParameterSet)]
	[OutputType(typeof(TboCredManEntryInfo))]
	public sealed class GetTBOCredManEntry : SmbCmdlet
	{
		private const string PathParameterSet = "Path";
		private const string InputParameterSet = "Input";
		private const int DefaultMaxBytes = 1024 * 1024;

		private static readonly byte[] DpapiMagic = new byte[]
		{
			0x01, 0x00, 0x00, 0x00, 0xD0, 0x8C, 0x9D, 0xDF, 0x01, 0x15,
			0xD1, 0x11, 0x8C, 0x7A, 0x00, 0xC0, 0x4F, 0xC2, 0x97, 0xEB
		};

		[Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true, ParameterSetName = PathParameterSet)]
		public string ServerName { get; set; } = string.Empty;

		[Parameter(Mandatory = true, Position = 1, ValueFromPipelineByPropertyName = true, ParameterSetName = PathParameterSet)]
		public string Path { get; set; } = string.Empty;

		[Parameter(Mandatory = true, ValueFromPipeline = true, ParameterSetName = InputParameterSet)]
		public TboCredManFileInfo? InputObject { get; set; }

		[Parameter]
		[ValidateRange(1, int.MaxValue)]
		public int MaxBytes { get; set; } = DefaultMaxBytes;

		[Parameter]
		public SwitchParameter IncludeRawBytes { get; set; }

		protected override void ProcessRecord(ISmbProviderInfo smb)
		{
			var input = this.InputObject;
			var serverName = input?.ServerName ?? NormalizeServerName(this.ServerName);
			if (string.IsNullOrWhiteSpace(serverName))
				throw new ArgumentException("ServerName must be provided.", nameof(this.ServerName));

			var sourcePath = input?.Path ?? this.Path;
			if (string.IsNullOrWhiteSpace(sourcePath))
				throw new ArgumentException("Path must be provided.", nameof(this.Path));

			var uncPath = ResolveToUncPath(sourcePath, nameof(this.Path));
			if (string.IsNullOrEmpty(uncPath.ShareName))
				throw new ArgumentException($"Path must include a share name: {uncPath}", nameof(this.Path));

			if (!string.IsNullOrEmpty(uncPath.ServerName)
				&& !uncPath.ServerName.Equals(serverName, StringComparison.OrdinalIgnoreCase))
				throw new ArgumentException($"ServerName '{serverName}' does not match UNC host '{uncPath.ServerName}'.", nameof(this.ServerName));

			var fileSystem = SmbFileSystemResolver.Resolve(smb);
			ReadCredManFile(smb, fileSystem, uncPath, input);
		}

		private void ReadCredManFile(
			ISmbProviderInfo smb,
			ISmbFileSystem fileSystem,
			UncPath path,
			TboCredManFileInfo? input)
		{
			byte[]? buffer = null;
			int bytesRead = 0;
			ulong? fileSize = input?.FileSize;
			try
			{
				using var file = fileSystem.OpenFileRead(path, CancellationToken.None);
				var length = file.Length;
				if (length >= 0)
					fileSize ??= (ulong)length;

				var scanLength = (int)Math.Min(length, this.MaxBytes);
				if (scanLength < 0)
					scanLength = this.MaxBytes;

				buffer = scanLength == 0 ? Array.Empty<byte>() : new byte[scanLength];
				using var stream = file.OpenRead();
				bytesRead = ReadPrefix(stream, buffer);
			}
			catch (NtstatusException ex) when (IsMissingPath(ex))
			{
				this.WriteWarning($"Get-TBOCredManEntry could not open {path}: {ex.StatusCode}.");
				return;
			}
			catch (NtstatusException ex) when (IsAccessDenied(ex))
			{
				this.WriteWarning($"Get-TBOCredManEntry was denied access to {path}: {ex.StatusCode}.");
				return;
			}
			catch (Exception ex)
			{
				smb.LogException($"Get-TBOCredManEntry failed to read {path}", ex);
				throw;
			}

			int? offset = FindDpapiOffset(buffer.AsSpan(0, bytesRead));
			this.WriteObject(new TboCredManEntryInfo
			{
				ServerName = input?.ServerName ?? path.ServerName,
				Scope = input?.Scope ?? string.Empty,
				UserName = input?.UserName,
				UserSid = input?.UserSid,
				ProfilePath = input?.ProfilePath,
				Container = input?.Container ?? string.Empty,
				VaultGuid = input?.VaultGuid,
				SourcePath = path.ToString(),
				FileSize = fileSize,
				FileCreationTime = input?.FileCreationTime,
				FileLastWriteTime = input?.FileLastWriteTime,
				FileLastChangeTime = input?.FileLastChangeTime,
				DpapiBlobOffset = offset,
				BytesScanned = bytesRead,
				RawBytes = this.IncludeRawBytes.IsPresent ? buffer?.Take(bytesRead).ToArray() : null
			});
		}

		private static int ReadPrefix(Stream stream, byte[] buffer)
		{
			if (buffer.Length == 0)
				return 0;

			int totalRead = 0;
			while (totalRead < buffer.Length)
			{
				var read = stream.Read(buffer, totalRead, buffer.Length - totalRead);
				if (read <= 0)
					break;
				totalRead += read;
			}

			return totalRead;
		}

		private static int? FindDpapiOffset(ReadOnlySpan<byte> buffer)
		{
			if (buffer.Length < DpapiMagic.Length)
				return null;

			var offset = buffer.IndexOf(DpapiMagic);
			return offset >= 0 ? offset : null;
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

		private static string NormalizeServerName(string? serverName)
		{
			return string.IsNullOrWhiteSpace(serverName)
				? string.Empty
				: serverName.TrimStart('\\');
		}

		private static bool IsMissingPath(NtstatusException ex)
		{
			return ex.StatusCode is Ntstatus.STATUS_OBJECT_NAME_NOT_FOUND
				or Ntstatus.STATUS_OBJECT_PATH_NOT_FOUND
				or Ntstatus.STATUS_OBJECT_NAME_INVALID;
		}

		private static bool IsAccessDenied(NtstatusException ex)
		{
			return ex.StatusCode is Ntstatus.STATUS_ACCESS_DENIED
				or Ntstatus.STATUS_PRIVILEGE_NOT_HELD;
		}
	}

	internal static class CredManLocator
	{
		internal const string DefaultShareName = "C$";

		private static readonly string[] UserCredentialRoots =
		{
			@"AppData\Local\Microsoft\Credentials"
		};

		private static readonly string[] UserVaultRoots =
		{
			@"AppData\Local\Microsoft\Vault"
		};

		private static readonly string[] MachineProfiles =
		{
			@"Windows\System32\config\systemprofile",
			@"Windows\ServiceProfiles\LocalService",
			@"Windows\ServiceProfiles\NetworkService"
		};

		internal static IReadOnlyList<TboCredManFileInfo> Enumerate(
			ISmbProviderInfo smb,
			string serverName,
			string shareName,
			CredManScope scope,
			IReadOnlyList<WildcardPattern> userFilters,
			bool includeSystemProfiles,
			Action<string>? writeWarning,
			Action<string>? writeVerbose,
			CancellationToken cancellationToken)
		{
			writeWarning ??= _ => { };
			writeVerbose ??= _ => { };

			var results = new List<TboCredManFileInfo>();

			if (scope.HasFlag(CredManScope.User))
				EnumerateUserProfiles(smb, serverName, shareName, userFilters, results, writeWarning, writeVerbose, cancellationToken);

			if (scope.HasFlag(CredManScope.Machine) && includeSystemProfiles)
				EnumerateMachineProfiles(smb, serverName, shareName, results, writeWarning, writeVerbose, cancellationToken);

			return results;
		}

		private static void EnumerateUserProfiles(
			ISmbProviderInfo smb,
			string serverName,
			string shareName,
			IReadOnlyList<WildcardPattern> userFilters,
			List<TboCredManFileInfo> results,
			Action<string> writeWarning,
			Action<string> writeVerbose,
			CancellationToken cancellationToken)
		{
			var usersRoot = UncPath.Parse($@"\\{serverName}\{shareName}\Users");
			var fileSystem = ResolveFileSystem(smb);

			ISmbDirectory? usersDir = null;
			try
			{
				usersDir = fileSystem.OpenDirectory(usersRoot, cancellationToken);
				foreach (var entry in usersDir.QueryEntries("*", Smb2Directory.Smb2DirQueryOptions.None, SecurityInfo.None, Smb2Directory.DefaultQueryBufferSize, cancellationToken))
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

					var profileRoot = usersRoot.Append(entry.FileName);
					EnumerateProfileContainers(
						smb,
						profileRoot,
						serverName,
						"User",
						entry.FileName,
						isSystemProfile: false,
						results,
						writeWarning,
						writeVerbose,
						cancellationToken);
				}
			}
			catch (NtstatusException ex) when (IsMissingPath(ex))
			{
				writeVerbose($"Get-TBOCredManFiles could not open {usersRoot}: {ex.StatusCode}.");
			}
			catch (NtstatusException ex) when (IsAccessDenied(ex))
			{
				writeWarning($"Get-TBOCredManFiles was denied access to {usersRoot}: {ex.StatusCode}.");
			}
			catch (Exception ex)
			{
				smb.LogException($"Get-TBOCredManFiles failed to enumerate {usersRoot}", ex);
				throw;
			}
			finally
			{
				if (usersDir != null)
					usersDir.Dispose();
			}
		}

		private static void EnumerateMachineProfiles(
			ISmbProviderInfo smb,
			string serverName,
			string shareName,
			List<TboCredManFileInfo> results,
			Action<string> writeWarning,
			Action<string> writeVerbose,
			CancellationToken cancellationToken)
		{
			foreach (var profile in MachineProfiles)
			{
				var profileRoot = UncPath.Parse($@"\\{serverName}\{shareName}\{profile}");
				var profileName = GetProfileName(profile);
				EnumerateProfileContainers(
					smb,
					profileRoot,
					serverName,
					"Machine",
					profileName,
					isSystemProfile: true,
					results,
					writeWarning,
					writeVerbose,
					cancellationToken);
			}
		}

		private static void EnumerateProfileContainers(
			ISmbProviderInfo smb,
			UncPath profileRoot,
			string serverName,
			string scope,
			string profileName,
			bool isSystemProfile,
			List<TboCredManFileInfo> results,
			Action<string> writeWarning,
			Action<string> writeVerbose,
			CancellationToken cancellationToken)
		{
			foreach (var relative in UserCredentialRoots)
			{
				var credRoot = profileRoot.Append(relative);
				EnumerateCredentialDirectory(
					smb,
					credRoot,
					serverName,
					scope,
					profileName,
					isSystemProfile,
					results,
					writeWarning,
					writeVerbose,
					cancellationToken);
			}

			foreach (var relative in UserVaultRoots)
			{
				var vaultRoot = profileRoot.Append(relative);
				EnumerateVaultDirectory(
					smb,
					vaultRoot,
					serverName,
					scope,
					profileName,
					isSystemProfile,
					results,
					writeWarning,
					writeVerbose,
					cancellationToken);
			}
		}

		private static void EnumerateCredentialDirectory(
			ISmbProviderInfo smb,
			UncPath directoryPath,
			string serverName,
			string scope,
			string profileName,
			bool isSystemProfile,
			List<TboCredManFileInfo> results,
			Action<string> writeWarning,
			Action<string> writeVerbose,
			CancellationToken cancellationToken)
		{
			EnumerateFiles(
				smb,
				directoryPath,
				entry => results.Add(new TboCredManFileInfo
				{
					ServerName = serverName,
					Scope = scope,
					UserName = profileName,
					UserSid = null,
					ProfilePath = GetProfilePath(directoryPath, UserCredentialRoots),
					Container = "Credentials",
					VaultGuid = null,
					FileName = entry.FileName ?? string.Empty,
					Path = directoryPath.Append(entry.FileName ?? string.Empty).ToString(),
					FileSize = entry.Size,
					FileCreationTime = entry.CreationTime,
					FileLastWriteTime = entry.LastWriteTime,
					FileLastChangeTime = entry.LastChangeTime,
					IsSystemProfile = isSystemProfile
				}),
				writeWarning,
				writeVerbose,
				cancellationToken);
		}

		private static void EnumerateVaultDirectory(
			ISmbProviderInfo smb,
			UncPath vaultRoot,
			string serverName,
			string scope,
			string profileName,
			bool isSystemProfile,
			List<TboCredManFileInfo> results,
			Action<string> writeWarning,
			Action<string> writeVerbose,
			CancellationToken cancellationToken)
		{
			var fileSystem = ResolveFileSystem(smb);
			ISmbDirectory? rootDir = null;
			try
			{
				rootDir = fileSystem.OpenDirectory(vaultRoot, cancellationToken);
				foreach (var entry in rootDir.QueryEntries("*", Smb2Directory.Smb2DirQueryOptions.None, SecurityInfo.None, Smb2Directory.DefaultQueryBufferSize, cancellationToken))
				{
					if (string.IsNullOrEmpty(entry.FileName))
						continue;
					if (entry.FileName is "." or "..")
						continue;

					bool isDirectory = (entry.FileAttributes & Winterop.FileAttributes.Directory) != 0;
					bool isReparse = (entry.FileAttributes & Winterop.FileAttributes.ReparsePoint) != 0;
					if (!isDirectory || isReparse)
						continue;

					var vaultGuid = TryParseGuid(entry.FileName);
					var vaultDir = vaultRoot.Append(entry.FileName);
					EnumerateFiles(
						smb,
						vaultDir,
						fileEntry => results.Add(new TboCredManFileInfo
						{
							ServerName = serverName,
							Scope = scope,
							UserName = profileName,
							UserSid = null,
							ProfilePath = GetProfilePath(vaultRoot, UserVaultRoots),
							Container = "Vault",
							VaultGuid = vaultGuid,
							FileName = fileEntry.FileName ?? string.Empty,
							Path = vaultDir.Append(fileEntry.FileName ?? string.Empty).ToString(),
							FileSize = fileEntry.Size,
							FileCreationTime = fileEntry.CreationTime,
							FileLastWriteTime = fileEntry.LastWriteTime,
							FileLastChangeTime = fileEntry.LastChangeTime,
							IsSystemProfile = isSystemProfile
						}),
						writeWarning,
						writeVerbose,
						cancellationToken);
				}
			}
			catch (NtstatusException ex) when (IsMissingPath(ex))
			{
				writeVerbose($"Get-TBOCredManFiles could not open {vaultRoot}: {ex.StatusCode}.");
			}
			catch (NtstatusException ex) when (IsAccessDenied(ex))
			{
				writeWarning($"Get-TBOCredManFiles was denied access to {vaultRoot}: {ex.StatusCode}.");
			}
			catch (Exception ex)
			{
				smb.LogException($"Get-TBOCredManFiles failed to enumerate {vaultRoot}", ex);
				throw;
			}
			finally
			{
				if (rootDir != null)
					rootDir.Dispose();
			}
		}

		private static void EnumerateFiles(
			ISmbProviderInfo smb,
			UncPath directoryPath,
			Action<Smb2DirEntry> handleFile,
			Action<string> writeWarning,
			Action<string> writeVerbose,
			CancellationToken cancellationToken)
		{
			var fileSystem = ResolveFileSystem(smb);
			ISmbDirectory? dir = null;
			try
			{
				dir = fileSystem.OpenDirectory(directoryPath, cancellationToken);
				foreach (var entry in dir.QueryEntries("*", Smb2Directory.Smb2DirQueryOptions.None, SecurityInfo.None, Smb2Directory.DefaultQueryBufferSize, cancellationToken))
				{
					if (string.IsNullOrEmpty(entry.FileName))
						continue;
					if (entry.FileName is "." or "..")
						continue;

					bool isDirectory = (entry.FileAttributes & Winterop.FileAttributes.Directory) != 0;
					if (isDirectory)
						continue;

					handleFile(entry);
				}
			}
			catch (NtstatusException ex) when (IsMissingPath(ex))
			{
				writeVerbose($"Get-TBOCredManFiles could not open {directoryPath}: {ex.StatusCode}.");
			}
			catch (NtstatusException ex) when (IsAccessDenied(ex))
			{
				writeWarning($"Get-TBOCredManFiles was denied access to {directoryPath}: {ex.StatusCode}.");
			}
			catch (Exception ex)
			{
				smb.LogException($"Get-TBOCredManFiles failed to enumerate {directoryPath}", ex);
				throw;
			}
			finally
			{
				if (dir != null)
					dir.Dispose();
			}
		}

		private static ISmbFileSystem ResolveFileSystem(ISmbProviderInfo smb)
		{
			return SmbFileSystemResolver.Resolve(smb);
		}

		private static string GetProfileName(string profileRoot)
		{
			if (string.IsNullOrWhiteSpace(profileRoot))
				return "SYSTEM";

			var parts = profileRoot.Split(new[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
			return parts.Length > 0 ? parts[parts.Length - 1] : profileRoot;
		}

		private static string? GetProfilePath(UncPath containerPath, string[] rootMarkers)
		{
			foreach (var marker in rootMarkers)
			{
				var index = containerPath.ShareRelativePath.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
				if (index >= 0)
				{
					var profileRelative = containerPath.ShareRelativePath.Substring(0, index).TrimEnd('\\');
					if (string.IsNullOrWhiteSpace(profileRelative))
						return null;
					return $@"\\{containerPath.ServerName}\{containerPath.ShareName}\{profileRelative}";
				}
			}

			return null;
		}

		private static string? TryParseGuid(string name)
		{
			if (string.IsNullOrWhiteSpace(name))
				return null;

			if (Guid.TryParse(name.Trim('{', '}'), out var guid))
				return guid.ToString();

			return null;
		}

		private static bool MatchesUserFilter(string name, IReadOnlyList<WildcardPattern> filters)
		{
			if (filters.Count == 0)
				return true;
			foreach (var pattern in filters)
			{
				if (pattern.IsMatch(name))
					return true;
			}

			return false;
		}

		private static bool IsMissingPath(NtstatusException ex)
		{
			return ex.StatusCode is Ntstatus.STATUS_OBJECT_NAME_NOT_FOUND
				or Ntstatus.STATUS_OBJECT_PATH_NOT_FOUND
				or Ntstatus.STATUS_OBJECT_NAME_INVALID;
		}

		private static bool IsAccessDenied(NtstatusException ex)
		{
			return ex.StatusCode is Ntstatus.STATUS_ACCESS_DENIED
				or Ntstatus.STATUS_PRIVILEGE_NOT_HELD;
		}
	}
}
