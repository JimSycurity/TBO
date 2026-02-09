using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal sealed class LocalVssShadowCopyInfo
	{
		internal LocalVssShadowCopyInfo(string id, string volumeName, string deviceObject, DateTime installDateUtc)
		{
			Id = id ?? throw new ArgumentNullException(nameof(id));
			VolumeName = volumeName ?? string.Empty;
			DeviceObject = deviceObject ?? throw new ArgumentNullException(nameof(deviceObject));
			InstallDateUtc = installDateUtc;
		}

		internal string Id { get; }
		internal string VolumeName { get; }
		internal string DeviceObject { get; }
		internal DateTime InstallDateUtc { get; }
	}

	internal static class LocalVssShadowCopyResolver
	{
		// Snapshot enumeration can be moderately expensive (WMI); cache briefly to avoid repeated queries
		// during provider operations like Get-ChildItem that open multiple directories.
		private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(15);
		private static readonly object CacheLock = new object();
		private static readonly Dictionary<string, CacheEntry> CacheByVolume = new Dictionary<string, CacheEntry>(StringComparer.OrdinalIgnoreCase);

		internal static bool TryResolveDeviceObject(
			string driveRoot,
			DateTime timeWarpTokenUtc,
			Action<string>? logDiagnostic,
			Action<string>? logWarning,
			out string deviceObject,
			out string? failureReason)
		{
			deviceObject = string.Empty;
			failureReason = null;

			if (!OperatingSystem.IsWindows())
			{
				failureReason = "VSS snapshot resolution is only supported on Windows.";
				return false;
			}

			if (string.IsNullOrWhiteSpace(driveRoot))
			{
				failureReason = "Drive root must be provided.";
				return false;
			}

			logDiagnostic ??= _ => { };
			logWarning ??= _ => { };

			var normalizedDriveRoot = NormalizeDriveRoot(driveRoot);

			string? volumeName = null;
			if (!TryGetVolumeNameForMountPoint(normalizedDriveRoot, out var volName, out var volErr))
			{
				logWarning($"VSS: GetVolumeNameForVolumeMountPoint failed for '{normalizedDriveRoot}': {volErr}. Falling back to drive-root matching.");
			}
			else
			{
				volumeName = volName;
				logDiagnostic($"VSS: volume name for '{normalizedDriveRoot}' is '{volumeName}'.");
			}

			var tokenUtc = EnsureUtc(timeWarpTokenUtc);

			var snapshots = GetSnapshotsForVolume(volumeName, normalizedDriveRoot, logDiagnostic, logWarning, out failureReason);
			if (snapshots == null)
				return false;

			if (snapshots.Count == 0)
			{
				failureReason = volumeName != null
					? $"No VSS shadow copies were found for volume '{volumeName}'."
					: $"No VSS shadow copies were found for drive '{normalizedDriveRoot}'.";
				return false;
			}

			LocalVssShadowCopyInfo? best = null;
			foreach (var snapshot in snapshots)
			{
				if (snapshot.InstallDateUtc > tokenUtc)
					continue;

				if (best == null || snapshot.InstallDateUtc > best.InstallDateUtc)
					best = snapshot;
			}

			if (best == null)
			{
				failureReason = $"No VSS shadow copy was found at or before {tokenUtc:O} for '{normalizedDriveRoot}'.";
				logWarning($"VSS: {failureReason}");
				return false;
			}

			deviceObject = best.DeviceObject;
			logDiagnostic($"VSS: selected shadow copy {best.Id} ({best.InstallDateUtc:O}) -> {best.DeviceObject}.");
			return true;
		}

		private static IReadOnlyList<LocalVssShadowCopyInfo>? GetSnapshotsForVolume(
			string? volumeName,
			string driveRoot,
			Action<string> logDiagnostic,
			Action<string> logWarning,
			out string? failureReason)
		{
			failureReason = null;

			var cacheKey = volumeName ?? driveRoot;
			lock (CacheLock)
			{
				if (CacheByVolume.TryGetValue(cacheKey, out var entry))
				{
					if (DateTime.UtcNow - entry.RefreshedUtc < CacheTtl)
						return entry.Snapshots;
				}
			}

			List<LocalVssShadowCopyInfo> snapshots;
			try
			{
				snapshots = QueryShadowCopies(volumeName, driveRoot, logDiagnostic);
			}
			catch (Exception ex)
			{
				failureReason = $"Failed to query VSS shadow copies via WMI: {ex.Message}";
				logWarning($"VSS: {failureReason}");
				return null;
			}

			snapshots.Sort((a, b) => a.InstallDateUtc.CompareTo(b.InstallDateUtc));

			lock (CacheLock)
			{
				CacheByVolume[cacheKey] = new CacheEntry(DateTime.UtcNow, snapshots);
			}

			return snapshots;
		}

		private static List<LocalVssShadowCopyInfo> QueryShadowCopies(string? volumeName, string driveRoot, Action<string> logDiagnostic)
		{
			var results = new List<LocalVssShadowCopyInfo>();

			using var searcher = new ManagementObjectSearcher(
				@"root\cimv2",
				"SELECT ID, InstallDate, DeviceObject, VolumeName FROM Win32_ShadowCopy");

			using var objects = searcher.Get();

			foreach (ManagementObject obj in objects)
			{
				var vol = obj["VolumeName"] as string;
				if (!IsVolumeMatch(vol, volumeName, driveRoot))
					continue;

				var id = obj["ID"] as string;
				var deviceObject = obj["DeviceObject"] as string;
				var installDateRaw = obj["InstallDate"] as string;
				if (string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(deviceObject) || string.IsNullOrWhiteSpace(installDateRaw))
					continue;

				DateTime installDate;
				try
				{
					installDate = ManagementDateTimeConverter.ToDateTime(installDateRaw);
				}
				catch
				{
					continue;
				}

				results.Add(new LocalVssShadowCopyInfo(
					id.Trim(),
					vol?.Trim() ?? string.Empty,
					deviceObject.Trim(),
					EnsureUtc(installDate)));
			}

			logDiagnostic($"VSS: found {results.Count} shadow copies for '{volumeName ?? driveRoot}'.");
			return results;
		}

		private static bool IsVolumeMatch(string? candidateVolumeName, string? targetVolumeName, string targetDriveRoot)
		{
			if (string.IsNullOrWhiteSpace(candidateVolumeName))
				return false;

			// Prefer exact volume GUID match when available.
			if (!string.IsNullOrWhiteSpace(targetVolumeName))
			{
				if (NormalizeVolumeName(candidateVolumeName).Equals(NormalizeVolumeName(targetVolumeName), StringComparison.OrdinalIgnoreCase))
					return true;
			}

			// Some providers may return a drive-root style name (ex: "C:\") instead of a volume GUID.
			if (NormalizeDriveRoot(candidateVolumeName).Equals(NormalizeDriveRoot(targetDriveRoot), StringComparison.OrdinalIgnoreCase))
				return true;

			return false;
		}

		private static DateTime EnsureUtc(DateTime value)
		{
			if (value.Kind == DateTimeKind.Utc)
				return value;

			// Treat unspecified as local, consistent with WMI ManagementDateTimeConverter behavior.
			return value.ToUniversalTime();
		}

		private static string NormalizeDriveRoot(string value)
		{
			var trimmed = value.Trim().Replace('/', '\\');
			if (trimmed.Length == 2 && char.IsLetter(trimmed[0]) && trimmed[1] == ':')
				trimmed += "\\";
			if (!trimmed.EndsWith("\\", StringComparison.Ordinal))
				trimmed += "\\";
			return trimmed;
		}

		private static string NormalizeVolumeName(string value)
		{
			var trimmed = value.Trim().Replace('/', '\\');
			if (!trimmed.EndsWith("\\", StringComparison.Ordinal))
				trimmed += "\\";
			return trimmed;
		}

		private static bool TryGetVolumeNameForMountPoint(string driveRoot, out string volumeName, out string? error)
		{
			volumeName = string.Empty;
			error = null;

			var sb = new StringBuilder(512);
			if (!GetVolumeNameForVolumeMountPoint(driveRoot, sb, sb.Capacity))
			{
				var err = Marshal.GetLastWin32Error();
				error = new Win32Exception(err).Message + $" (0x{err:X8})";
				return false;
			}

			volumeName = sb.ToString();
			if (string.IsNullOrWhiteSpace(volumeName))
			{
				error = "GetVolumeNameForVolumeMountPoint returned an empty volume name.";
				return false;
			}

			volumeName = NormalizeVolumeName(volumeName);
			return true;
		}

		[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		private static extern bool GetVolumeNameForVolumeMountPoint(string lpszVolumeMountPoint, StringBuilder lpszVolumeName, int cchBufferLength);

		private sealed class CacheEntry
		{
			internal CacheEntry(DateTime refreshedUtc, IReadOnlyList<LocalVssShadowCopyInfo> snapshots)
			{
				RefreshedUtc = refreshedUtc;
				Snapshots = snapshots;
			}

			internal DateTime RefreshedUtc { get; }
			internal IReadOnlyList<LocalVssShadowCopyInfo> Snapshots { get; }
		}
	}
}

