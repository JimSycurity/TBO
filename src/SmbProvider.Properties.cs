using System;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Provider;
using Titanis.Net;
using Titanis.Smb2;
using Smb2AccessRights = Titanis.Smb2.Smb2FileAccessRights;
using Winterop = Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public partial class SmbProvider : IPropertyCmdletProvider
	{
		public void GetProperty(string path, Collection<string> providerSpecificPickList)
		{
			if (string.IsNullOrWhiteSpace(path))
				throw new ArgumentException("Path must be provided.", nameof(path));

			var snapshotPath = ResolveSnapshotPath(path);
			UncPath uncPath = snapshotPath.ResolvedPath;
			if (string.IsNullOrEmpty(uncPath.ShareRelativePath))
				throw new ArgumentException("Path must include a file or directory name.", nameof(path));

			this.BeginOperation(cancellationToken =>
			{
				Smb2OpenFileObjectBase? file = null;
				try
				{
					var createInfo = CreateAttributeReadInfo();
					createInfo.TimeWarpToken = snapshotPath.TimeWarpToken;
					file = this.smb.SmbClient.CreateFileAsync(uncPath, createInfo, System.IO.FileAccess.Read, cancellationToken).Result;
					var basicInfo = file.GetBasicInfoAsync(cancellationToken).Result;

					var output = new PSObject();
					AddPropertyIfRequested(output, providerSpecificPickList, "CreationTime", basicInfo.CreationTime);
					AddPropertyIfRequested(output, providerSpecificPickList, "LastAccessTime", basicInfo.LastAccessTime);
					AddPropertyIfRequested(output, providerSpecificPickList, "LastWriteTime", basicInfo.LastWriteTime);
					AddPropertyIfRequested(output, providerSpecificPickList, "ChangeTime", basicInfo.ChangeTime);
					AddPropertyIfRequested(output, providerSpecificPickList, "Attributes", basicInfo.Attributes);

					this.WritePropertyObject(output, snapshotPath.OriginalPath.ToString());
				}
				finally
				{
					if (file != null)
						file.CloseAsync(cancellationToken).GetAwaiter().GetResult();
				}
			});
		}

		public object GetPropertyDynamicParameters(string path, Collection<string> providerSpecificPickList)
		{
			return null;
		}

		public void SetProperty(string path, PSObject propertyValue)
		{
			if (string.IsNullOrWhiteSpace(path))
				throw new ArgumentException("Path must be provided.", nameof(path));

			var snapshotPath = ResolveSnapshotPath(path);
			if (snapshotPath.HasTimeWarpToken)
				throw new NotSupportedException("Snapshot paths are read-only.");

			UncPath uncPath = snapshotPath.ResolvedPath;
			if (string.IsNullOrEmpty(uncPath.ShareRelativePath))
				throw new ArgumentException("Path must include a file or directory name.", nameof(path));

			if (propertyValue == null)
				return;

			var update = ParseBasicInfoUpdate(propertyValue);
			if (!update.HasChanges)
				return;

			this.BeginOperation(cancellationToken =>
			{
				Smb2OpenFileObjectBase? file = null;
				try
				{
					file = this.smb.SmbClient.CreateFileAsync(uncPath, CreateAttributeUpdateInfo(), System.IO.FileAccess.ReadWrite, cancellationToken).Result;

					var attributes = update.AttributesProvided
						? update.Attributes
						: file.GetBasicInfoAsync(cancellationToken).Result.Attributes;

					file.SetBasicInfoAsync(
						update.CreationTime,
						update.LastAccessTime,
						update.LastWriteTime,
						update.ChangeTime,
						attributes,
						cancellationToken).GetAwaiter().GetResult();
				}
				finally
				{
					if (file != null)
						file.CloseAsync(cancellationToken).GetAwaiter().GetResult();
				}
			});
		}

		public object SetPropertyDynamicParameters(string path, PSObject propertyValue)
		{
			return null;
		}

		public void ClearProperty(string path, Collection<string> propertyToClear)
		{
			throw new NotSupportedException("Clearing SMB properties is not supported.");
		}

		public object ClearPropertyDynamicParameters(string path, Collection<string> propertyToClear)
		{
			return null;
		}

		private static Smb2CreateInfo CreateAttributeReadInfo()
		{
			return new Smb2CreateInfo
			{
				CreateDisposition = Smb2CreateDisposition.Open,
				DesiredAccess = (uint)Smb2AccessRights.ReadAttributes,
				ShareAccess = Smb2ShareAccess.ReadWriteDelete,
				FileAttributes = Winterop.FileAttributes.Normal,
				CreateOptions = Smb2FileCreateOptions.SynchronousIoNonalert
					| Smb2FileCreateOptions.OpenReparsePoint
					| Smb2FileCreateOptions.OpenForBackupIntent,
				ImpersonationLevel = Smb2ImpersonationLevel.Impersonation
			};
		}

		private static Smb2CreateInfo CreateAttributeUpdateInfo()
		{
			return new Smb2CreateInfo
			{
				CreateDisposition = Smb2CreateDisposition.Open,
				DesiredAccess = (uint)(Smb2AccessRights.ReadAttributes | Smb2AccessRights.WriteAttributes),
				ShareAccess = Smb2ShareAccess.ReadWriteDelete,
				FileAttributes = Winterop.FileAttributes.Normal,
				CreateOptions = Smb2FileCreateOptions.SynchronousIoNonalert
					| Smb2FileCreateOptions.OpenReparsePoint
					| Smb2FileCreateOptions.OpenForBackupIntent,
				ImpersonationLevel = Smb2ImpersonationLevel.Impersonation
			};
		}

		private static void AddPropertyIfRequested(PSObject output, Collection<string> pickList, string name, object value)
		{
			if (pickList != null && pickList.Count > 0)
			{
				bool matched = false;
				foreach (var item in pickList)
				{
					if (string.Equals(item, name, StringComparison.OrdinalIgnoreCase))
					{
						matched = true;
						break;
					}
				}
				if (!matched)
					return;
			}

			output.Properties.Add(new PSNoteProperty(name, value));
		}

		private static BasicInfoUpdate ParseBasicInfoUpdate(PSObject propertyValue)
		{
			var update = new BasicInfoUpdate();

			foreach (var prop in propertyValue.Properties)
			{
				if (prop == null)
					continue;

				if (prop.Value == null)
					continue;

				var propName = prop.Name ?? string.Empty;
				if (propName.Equals("CreationTime", StringComparison.OrdinalIgnoreCase))
				{
					update.CreationTime = NormalizeTimestamp(prop.Value, false);
					continue;
				}
				if (propName.Equals("CreationTimeUtc", StringComparison.OrdinalIgnoreCase))
				{
					update.CreationTime = NormalizeTimestamp(prop.Value, true);
					continue;
				}
				if (propName.Equals("LastAccessTime", StringComparison.OrdinalIgnoreCase))
				{
					update.LastAccessTime = NormalizeTimestamp(prop.Value, false);
					continue;
				}
				if (propName.Equals("LastAccessTimeUtc", StringComparison.OrdinalIgnoreCase))
				{
					update.LastAccessTime = NormalizeTimestamp(prop.Value, true);
					continue;
				}
				if (propName.Equals("LastWriteTime", StringComparison.OrdinalIgnoreCase))
				{
					update.LastWriteTime = NormalizeTimestamp(prop.Value, false);
					continue;
				}
				if (propName.Equals("LastWriteTimeUtc", StringComparison.OrdinalIgnoreCase))
				{
					update.LastWriteTime = NormalizeTimestamp(prop.Value, true);
					continue;
				}
				if (propName.Equals("ChangeTime", StringComparison.OrdinalIgnoreCase))
				{
					update.ChangeTime = NormalizeTimestamp(prop.Value, false);
					continue;
				}
				if (propName.Equals("ChangeTimeUtc", StringComparison.OrdinalIgnoreCase))
				{
					update.ChangeTime = NormalizeTimestamp(prop.Value, true);
					continue;
				}
				if (propName.Equals("Attributes", StringComparison.OrdinalIgnoreCase)
					|| propName.Equals("FileAttributes", StringComparison.OrdinalIgnoreCase))
				{
					update.Attributes = ConvertAttributes(prop.Value);
					update.AttributesProvided = true;
					continue;
				}

				throw new ArgumentException($"Unsupported property name: {prop.Name}");
			}

			return update;
		}

		private static DateTime? NormalizeTimestamp(object value, bool isUtc)
		{
			if (value == null)
				return null;

			var converted = LanguagePrimitives.ConvertTo<DateTime>(value);
			if (isUtc)
			{
				return converted.Kind switch
				{
					DateTimeKind.Utc => converted,
					DateTimeKind.Unspecified => DateTime.SpecifyKind(converted, DateTimeKind.Utc),
					_ => converted.ToUniversalTime()
				};
			}

			return converted.Kind == DateTimeKind.Unspecified
				? DateTime.SpecifyKind(converted, DateTimeKind.Local)
				: converted;
		}

		private static Winterop.FileAttributes ConvertAttributes(object value)
		{
			if (value is Winterop.FileAttributes attrs)
				return attrs;

			if (value is string text && Enum.TryParse<Winterop.FileAttributes>(text, true, out var parsed))
				return parsed;

			var numeric = LanguagePrimitives.ConvertTo<int>(value);
			return (Winterop.FileAttributes)numeric;
		}

		private sealed class BasicInfoUpdate
		{
			public DateTime? CreationTime { get; set; }
			public DateTime? LastAccessTime { get; set; }
			public DateTime? LastWriteTime { get; set; }
			public DateTime? ChangeTime { get; set; }
			public Winterop.FileAttributes Attributes { get; set; }
			public bool AttributesProvided { get; set; }
			public bool HasChanges => CreationTime.HasValue || LastAccessTime.HasValue || LastWriteTime.HasValue || ChangeTime.HasValue || AttributesProvided;
		}
	}
}
