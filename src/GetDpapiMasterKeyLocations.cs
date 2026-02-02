using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Management.Automation;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Titanis.Net;
using Titanis.Smb2;
using Titanis.Winterop;
using Titanis.Winterop.Security;
using Winterop = Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	[Flags]
	public enum DpapiMasterKeyScope
	{
		None = 0,
		Machine = 1,
		User = 2,
		All = Machine | User
	}

	public sealed class TboDpapiMasterKeyLocationInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string Scope { get; init; } = string.Empty;
		public string? UserSid { get; init; }
		public string KeyPath { get; init; } = string.Empty;
		public string? MasterKeyGuid { get; init; }
		public bool IsPreferred { get; init; }
		public DateTime? FileCreationTime { get; init; }
		public DateTime? FileLastWriteTime { get; init; }
		public DateTime? FileLastChangeTime { get; init; }
	}

	[Cmdlet(VerbsCommon.Get, "TBODpapiMasterKeyLocations")]
	[OutputType(typeof(TboDpapiMasterKeyLocationInfo))]
	public sealed class GetTBODpapiMasterKeyLocations : SmbCmdlet
	{
		[Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true)]
		public string ServerName { get; set; } = string.Empty;

		[Parameter]
		public DpapiMasterKeyScope Scope { get; set; } = DpapiMasterKeyScope.All;

		[Parameter]
		public string ShareName { get; set; } = DpapiMasterKeyLocator.DefaultShareName;

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

			var progressId = 17;
			var progressActivity = $"Enumerating DPAPI master key locations on {serverName}";
			var progressCallback = new Action<string>(status =>
			{
				this.WriteProgress(new ProgressRecord(progressId, progressActivity, status)
				{
					RecordType = ProgressRecordType.Processing
				});
			});

			var locations = DpapiMasterKeyLocator.Enumerate(
				smb,
				serverName,
				shareName,
				this.Scope,
				message => this.WriteWarning(message),
				progressCallback,
				message => this.WriteVerbose(message),
				cancellationToken);

			foreach (var location in locations)
			{
				this.WriteObject(location);
			}

			this.WriteProgress(new ProgressRecord(progressId, progressActivity, "Completed")
			{
				RecordType = ProgressRecordType.Completed
			});
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
	}

	internal static class DpapiMasterKeyLocator
	{
		internal const string DefaultShareName = "C$";

		private static readonly string[] SystemProtectRoots =
		{
			@"Windows\System32\Microsoft\Protect",
			@"ProgramData\Microsoft\Protect"
		};

		internal static IReadOnlyList<TboDpapiMasterKeyLocationInfo> Enumerate(
			ISmbProviderInfo smb,
			string serverName,
			string shareName,
			DpapiMasterKeyScope scope,
			Action<string>? writeWarning,
			Action<string>? writeProgress,
			Action<string>? writeVerbose,
			CancellationToken cancellationToken)
		{
			writeWarning ??= _ => { };
			writeProgress ??= _ => { };
			writeVerbose ??= _ => { };

			var results = new List<TboDpapiMasterKeyLocationInfo>();
			if (scope.HasFlag(DpapiMasterKeyScope.Machine))
				EnumerateMachineMasterKeys(smb, serverName, shareName, results, writeWarning, writeProgress, writeVerbose, cancellationToken);
			if (scope.HasFlag(DpapiMasterKeyScope.User))
				EnumerateUserMasterKeys(smb, serverName, shareName, results, writeWarning, writeProgress, writeVerbose, cancellationToken);

			return results;
		}

		private static void EnumerateMachineMasterKeys(
			ISmbProviderInfo smb,
			string serverName,
			string shareName,
			List<TboDpapiMasterKeyLocationInfo> results,
			Action<string> writeWarning,
			Action<string> writeProgress,
			Action<string> writeVerbose,
			CancellationToken cancellationToken)
		{
			foreach (var root in SystemProtectRoots)
			{
				var rootPath = UncPath.Parse($@"\\{serverName}\{shareName}\{root}");
				writeProgress($"Scanning {rootPath} for machine master keys.");
				EnumerateProtectRoot(smb, rootPath, "Machine", results, writeWarning, writeProgress, writeVerbose, cancellationToken);
			}
		}

		private static void EnumerateUserMasterKeys(
			ISmbProviderInfo smb,
			string serverName,
			string shareName,
			List<TboDpapiMasterKeyLocationInfo> results,
			Action<string> writeWarning,
			Action<string> writeProgress,
			Action<string> writeVerbose,
			CancellationToken cancellationToken)
		{
			var userRoots = new[]
			{
				$@"\\{serverName}\{shareName}\Users",
				$@"\\{serverName}\{shareName}\Documents and Settings"
			};

			foreach (var rootPath in userRoots)
			{
				if (rootPath.EndsWith(@"\Documents and Settings", StringComparison.OrdinalIgnoreCase))
				{
					writeVerbose($"Get-TBODpapiMasterKeyLocations skipping legacy profile root {rootPath}.");
					continue;
				}

				writeProgress($"Scanning {rootPath} for user profiles.");
				EnumerateUserRoot(smb, UncPath.Parse(rootPath), serverName, shareName, results, writeWarning, writeProgress, writeVerbose, cancellationToken);
			}
		}

		private static void EnumerateUserRoot(
			ISmbProviderInfo smb,
			UncPath usersRoot,
			string serverName,
			string shareName,
			List<TboDpapiMasterKeyLocationInfo> results,
			Action<string> writeWarning,
			Action<string> writeProgress,
			Action<string> writeVerbose,
			CancellationToken cancellationToken)
		{
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

					writeProgress($"Scanning {usersRoot.Append(entry.FileName)} for DPAPI master keys.");

					var roamingRoot = UncPath.Parse($@"\\{serverName}\{shareName}\{usersRoot.ShareRelativePath}\{entry.FileName}\AppData\Roaming\Microsoft\Protect");
					var localRoot = UncPath.Parse($@"\\{serverName}\{shareName}\{usersRoot.ShareRelativePath}\{entry.FileName}\AppData\Local\Microsoft\Protect");

					EnumerateProtectRoot(smb, roamingRoot, "User", results, writeWarning, writeProgress, writeVerbose, cancellationToken);
					EnumerateProtectRoot(smb, localRoot, "User", results, writeWarning, writeProgress, writeVerbose, cancellationToken);
				}
			}
			catch (NtstatusException ex) when (IsMissingPath(ex))
			{
				writeVerbose($"Get-TBODpapiMasterKeyLocations could not open {usersRoot}: {ex.StatusCode}.");
			}
			catch (NtstatusException ex) when (IsAccessDenied(ex))
			{
				writeWarning($"Get-TBODpapiMasterKeyLocations was denied access to {usersRoot}: {ex.StatusCode}.");
			}
			catch (Exception ex)
			{
				smb.LogException($"Get-TBODpapiMasterKeyLocations failed to enumerate {usersRoot}", ex);
				throw;
			}
			finally
			{
				if (usersDir != null)
					usersDir.Dispose();
			}
		}

		private static void EnumerateProtectRoot(
			ISmbProviderInfo smb,
			UncPath rootPath,
			string scope,
			List<TboDpapiMasterKeyLocationInfo> results,
			Action<string> writeWarning,
			Action<string> writeProgress,
			Action<string> writeVerbose,
			CancellationToken cancellationToken)
		{
			var fileSystem = ResolveFileSystem(smb);
			ISmbDirectory? rootDir = null;
			try
			{
				rootDir = fileSystem.OpenDirectory(rootPath, cancellationToken);
				foreach (var entry in rootDir.QueryEntries("*", Smb2Directory.Smb2DirQueryOptions.QueryReparseInfo, SecurityInfo.None, Smb2Directory.DefaultQueryBufferSize, cancellationToken))
				{
					if (string.IsNullOrEmpty(entry.FileName))
						continue;
					if (entry.FileName is "." or "..")
						continue;

					bool isDirectory = (entry.FileAttributes & Winterop.FileAttributes.Directory) != 0;
					bool isReparse = (entry.FileAttributes & Winterop.FileAttributes.ReparsePoint) != 0;
					if (!isDirectory || isReparse)
						continue;
					if (!IsSid(entry.FileName))
						continue;

					var sidPath = rootPath.Append(entry.FileName);
					writeProgress($"Scanning {sidPath} for {scope} master keys.");
					EnumerateMasterKeyDirectory(smb, sidPath, rootPath.ServerName, scope, entry.FileName, results, writeWarning, writeVerbose, cancellationToken);
				}
			}
			catch (NtstatusException ex) when (IsMissingPath(ex))
			{
				writeVerbose($"Get-TBODpapiMasterKeyLocations could not open {rootPath}: {ex.StatusCode}.");
			}
			catch (NtstatusException ex) when (IsAccessDenied(ex))
			{
				writeWarning($"Get-TBODpapiMasterKeyLocations was denied access to {rootPath}: {ex.StatusCode}.");
			}
			catch (Exception ex)
			{
				smb.LogException($"Get-TBODpapiMasterKeyLocations failed to enumerate {rootPath}", ex);
				throw;
			}
			finally
			{
				if (rootDir != null)
					rootDir.Dispose();
			}
		}

		private static void EnumerateMasterKeyDirectory(
			ISmbProviderInfo smb,
			UncPath directoryPath,
			string serverName,
			string scope,
			string userSid,
			List<TboDpapiMasterKeyLocationInfo> results,
			Action<string> writeWarning,
			Action<string> writeVerbose,
			CancellationToken cancellationToken)
		{
			Guid? preferredGuid = TryReadPreferredGuid(smb, directoryPath, cancellationToken);

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

					if (!TryParseGuid(entry.FileName, out var guid))
						continue;

					results.Add(new TboDpapiMasterKeyLocationInfo
					{
						ServerName = serverName,
						Scope = scope,
						UserSid = userSid,
						KeyPath = directoryPath.Append(entry.FileName).ToString(),
						MasterKeyGuid = guid.ToString(),
						IsPreferred = preferredGuid.HasValue && preferredGuid.Value == guid,
						FileCreationTime = entry.CreationTime,
						FileLastWriteTime = entry.LastWriteTime,
						FileLastChangeTime = entry.LastChangeTime
					});
				}
			}
			catch (NtstatusException ex) when (IsMissingPath(ex))
			{
				writeVerbose($"Get-TBODpapiMasterKeyLocations could not open {directoryPath}: {ex.StatusCode}.");
			}
			catch (NtstatusException ex) when (IsAccessDenied(ex))
			{
				writeWarning($"Get-TBODpapiMasterKeyLocations was denied access to {directoryPath}: {ex.StatusCode}.");
			}
			catch (Exception ex)
			{
				smb.LogException($"Get-TBODpapiMasterKeyLocations failed to enumerate {directoryPath}", ex);
				throw;
			}
			finally
			{
				if (dir != null)
					dir.Dispose();
			}
		}

		private static Guid? TryReadPreferredGuid(ISmbProviderInfo smb, UncPath directoryPath, CancellationToken cancellationToken)
		{
			var fileSystem = ResolveFileSystem(smb);
			var preferredPath = directoryPath.Append("Preferred");
			byte[]? bytes = null;
			try
			{
				using var file = fileSystem.OpenFileRead(preferredPath, cancellationToken);
				using var stream = file.OpenRead();
				using var memory = new MemoryStream();
				stream.CopyTo(memory);
				bytes = memory.ToArray();
			}
			catch (NtstatusException ex) when (IsMissingPath(ex))
			{
				return null;
			}
			catch (NtstatusException ex) when (IsAccessDenied(ex))
			{
				return null;
			}
			catch (Win32Exception)
			{
				return null;
			}
			catch (Exception ex)
			{
				smb.LogException($"Get-TBODpapiMasterKeyLocations failed to read {preferredPath}", ex);
				return null;
			}

			return TryParseGuidFromBytes(bytes);
		}

		private static ISmbFileSystem ResolveFileSystem(ISmbProviderInfo smb)
		{
			return SmbFileSystemResolver.Resolve(smb);
		}

		private static Guid? TryParseGuidFromBytes(byte[]? bytes)
		{
			if (bytes == null || bytes.Length == 0)
				return null;

			var text = TryDecodeGuidString(bytes, Encoding.Unicode)
				?? TryDecodeGuidString(bytes, Encoding.ASCII);
			if (!string.IsNullOrWhiteSpace(text))
			{
				var match = GuidPattern.Match(text);
				if (match.Success && Guid.TryParse(match.Value, out var parsedText))
					return parsedText;
			}

			if (bytes.Length >= 20)
			{
				var declaredLength = BitConverter.ToInt32(bytes, 0);
				if (declaredLength == 16)
				{
					try
					{
						return new Guid(bytes.AsSpan(4, 16));
					}
					catch
					{
					}
				}
			}

			if (bytes.Length == 16)
			{
				try
				{
					return new Guid(bytes);
				}
				catch
				{
				}
			}

			return null;
		}

		private static string? TryDecodeGuidString(byte[] bytes, Encoding encoding)
		{
			try
			{
				var text = encoding.GetString(bytes);
				text = text.Trim('\0', '\r', '\n', ' ');
				return string.IsNullOrWhiteSpace(text) ? null : text;
			}
			catch
			{
				return null;
			}
		}

		private static bool TryParseGuid(string name, out Guid guid)
		{
			guid = Guid.Empty;
			if (string.IsNullOrWhiteSpace(name))
				return false;

			var trimmed = name.Trim();
			if (trimmed.StartsWith("BK-", StringComparison.OrdinalIgnoreCase))
				trimmed = trimmed.Substring(3);
			trimmed = trimmed.Trim('{', '}');

			return Guid.TryParse(trimmed, out guid);
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

		private static bool IsSid(string name)
		{
			if (string.IsNullOrWhiteSpace(name))
				return false;
			return SidPattern.IsMatch(name);
		}

		private static readonly Regex SidPattern = new(
			@"^S-1-\d+(-\d+)+$",
			RegexOptions.Compiled | RegexOptions.IgnoreCase);

		private static readonly Regex GuidPattern = new(
			@"\b[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
			RegexOptions.Compiled);
	}
}
