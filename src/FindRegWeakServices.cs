using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Management.Automation;
using System.Security.AccessControl;
using System.Threading;
using Titanis.Msrpc.Msrrp;
using Titanis.Msrpc.Msscmr;
using Titanis.Winterop;
using Titanis.Winterop.Security;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboRegWeakServiceInfo
	{
		public TboRegWeakServiceInfo(
			string serverName,
			string serviceName,
			string keyPath,
			string trusteeSid,
			WellKnownSid trusteeWellKnownSid,
			AccessControlEntryType aceType,
			uint accessMask,
			string accessMaskText,
			IReadOnlyList<string> accessRights,
			ServiceAccessRights serviceAccess,
			StandardAccessRights standardAccessRights)
		{
			this.ServerName = serverName;
			this.ServiceName = serviceName;
			this.KeyPath = keyPath;
			this.TrusteeSid = trusteeSid;
			this.TrusteeWellKnownSid = trusteeWellKnownSid;
			this.AceType = aceType;
			this.AccessMask = accessMask;
			this.AccessMaskText = accessMaskText;
			this.AccessRights = accessRights;
			this.ServiceAccess = serviceAccess;
			this.StandardAccessRights = standardAccessRights;
		}

		public string ServerName { get; }
		public string ServiceName { get; }
		public string KeyPath { get; }
		public string TrusteeSid { get; }
		public WellKnownSid TrusteeWellKnownSid { get; }
		public AccessControlEntryType AceType { get; }
		public uint AccessMask { get; }
		public string AccessMaskText { get; }
		public IReadOnlyList<string> AccessRights { get; }
		public ServiceAccessRights ServiceAccess { get; }
		public StandardAccessRights StandardAccessRights { get; }
	}

	[Cmdlet(VerbsCommon.Find, "TBORegWeakServices")]
	[OutputType(typeof(TboRegWeakServiceInfo))]
	public sealed class FindTBORegWeakServices : ServiceRegistryCmdletBase
	{
		private const uint GenericAllMask = 0x10000000;
		private const uint GenericExecuteMask = 0x20000000;
		private const uint GenericWriteMask = 0x40000000;
		private const uint GenericReadMask = 0x80000000;
		private const uint DefaultInterestingAccessMask =
			(uint)ServiceAccessRights.AllRights |
			(uint)ServiceAccessRights.ChangeConfig |
			(uint)StandardAccessRights.WriteDac |
			(uint)StandardAccessRights.WriteOwner |
			GenericWriteMask;

		private static readonly HashSet<WellKnownSid> UninterestingSids = new()
		{
			WellKnownSid.BuiltinAdministrators,
			WellKnownSid.LocalSystem,
			WellKnownSid.Administrator
		};

		[Parameter(Position = 1)]
		public string Path { get; set; } = DefaultServicesPath;

		[Parameter(Position = 2, ValueFromPipelineByPropertyName = true)]
		[Alias("ServiceName", "KeyName")]
		public string[]? Name { get; set; }

		[Parameter]
		public uint? AccessMask { get; set; }

		[Parameter]
		public SwitchParameter IncludeUninteresting { get; set; }

		[Parameter]
		public SwitchParameter IgnoreServiceSids { get; set; }

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			var basePath = string.IsNullOrWhiteSpace(this.Path) ? DefaultServicesPath : this.Path;
			var parsedPath = ParseRegistryPath(basePath, nameof(this.Path));
			var useDefaultAccessMask = !this.AccessMask.HasValue;
			var interestingAccessMask = ResolveAccessMask();

			ExecuteRegistryOperation(smb, cancellationToken, session =>
			{
				using var servicesKey = OpenRegistryKey(
					session.Client,
					parsedPath,
					RegistryAccessRights.EnumerateSubkeys | RegistryAccessRights.QueryValue,
					cancellationToken);

				var keyInfo = servicesKey.QueryInfo(cancellationToken).GetAwaiter().GetResult();
				var requestedNames = FilterNames(this.Name);
				if (requestedNames.Count > 0)
				{
					ProcessRequestedNames(
						smb,
						session.Client,
						parsedPath,
						servicesKey,
						keyInfo,
						requestedNames,
						interestingAccessMask,
						useDefaultAccessMask,
						cancellationToken);
					return;
				}

				var subkeys = CollectServiceSubkeys(
					smb,
					servicesKey,
					keyInfo,
					parsedPath,
					cancellationToken,
					"Find-TBORegWeakServices");
				foreach (var subkey in subkeys)
				{
					if (string.IsNullOrWhiteSpace(subkey.KeyName))
						continue;

					TryScanService(
						smb,
						session.Client,
						parsedPath,
						subkey.KeyName,
						interestingAccessMask,
						useDefaultAccessMask,
						cancellationToken,
						warnOnMissing: false);
				}
			});
		}

		private void ProcessRequestedNames(
			ISmbProviderInfo smb,
			IRegistryClient client,
			RegistryPathSpec servicesPath,
			IRegistryKey servicesKey,
			RegistryKeyInfo servicesInfo,
			List<string> requestedNames,
			uint interestingAccessMask,
			bool useDefaultAccessMask,
			CancellationToken cancellationToken)
		{
			var exactNames = new List<string>();
			var wildcardPatterns = new List<WildcardPattern>();
			var wildcardInputs = new List<string>();
			foreach (var name in requestedNames)
			{
				if (WildcardPattern.ContainsWildcardCharacters(name))
				{
					wildcardPatterns.Add(new WildcardPattern(name, WildcardOptions.IgnoreCase));
					wildcardInputs.Add(name);
				}
				else
					exactNames.Add(name);
			}

			var checkedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
			foreach (var name in exactNames)
			{
				if (string.IsNullOrWhiteSpace(name))
					continue;

				if (TryScanService(smb, client, servicesPath, name, interestingAccessMask, useDefaultAccessMask, cancellationToken, warnOnMissing: true))
					checkedNames.Add(name);
			}

			if (wildcardPatterns.Count == 0)
				return;

			var subkeys = CollectServiceSubkeys(
				smb,
				servicesKey,
				servicesInfo,
				servicesPath,
				cancellationToken,
				"Find-TBORegWeakServices");
			var wildcardMatched = false;
			foreach (var subkey in subkeys)
			{
				var keyName = subkey.KeyName;
				if (string.IsNullOrWhiteSpace(keyName) || checkedNames.Contains(keyName))
					continue;

				if (!MatchesAnyPattern(wildcardPatterns, keyName))
					continue;

				wildcardMatched = true;
				if (TryScanService(smb, client, servicesPath, keyName, interestingAccessMask, useDefaultAccessMask, cancellationToken, warnOnMissing: false))
					checkedNames.Add(keyName);
			}

			if (!wildcardMatched)
				this.LogWarning(smb, $"No service keys matched pattern(s): {string.Join(", ", wildcardInputs)}.");
		}

		private bool TryScanService(
			ISmbProviderInfo smb,
			IRegistryClient client,
			RegistryPathSpec basePath,
			string serviceName,
			uint interestingAccessMask,
			bool useDefaultAccessMask,
			CancellationToken cancellationToken,
			bool warnOnMissing)
		{
			try
			{
				ScanService(smb, client, basePath, serviceName, interestingAccessMask, useDefaultAccessMask, cancellationToken);
				return true;
			}
			catch (NtstatusException ex) when (ex.StatusCode == Ntstatus.STATUS_PIPE_BUSY)
			{
				try
				{
					return ExecuteRegistryOperation(
						smb,
						cancellationToken,
						session =>
						{
							ScanService(smb, session.Client, basePath, serviceName, interestingAccessMask, useDefaultAccessMask, cancellationToken);
							return true;
						});
				}
				catch (NtstatusException retryEx) when (retryEx.StatusCode == Ntstatus.STATUS_PIPE_BUSY)
				{
					this.LogWarning(smb, $"Find-TBORegWeakServices failed to read service '{serviceName}': {retryEx.Message}");
				}
				catch (Exception retryEx)
				{
					this.LogException(smb, $"Find-TBORegWeakServices failed to read service '{serviceName}'", retryEx);
					this.LogWarning(smb, $"Find-TBORegWeakServices failed to read service '{serviceName}': {retryEx.Message}");
				}
			}
			catch (Win32Exception ex) when (IsMissingKey(ex))
			{
				if (warnOnMissing)
					this.LogWarning(smb, $"Service key not found: {basePath.KeyPath}\\{serviceName}");
			}
			catch (Exception ex)
			{
				this.LogException(smb, $"Find-TBORegWeakServices failed to read service '{serviceName}'", ex);
				this.LogWarning(smb, $"Find-TBORegWeakServices failed to read service '{serviceName}': {ex.Message}");
			}

			return false;
		}

		private void ScanService(
			ISmbProviderInfo smb,
			IRegistryClient client,
			RegistryPathSpec basePath,
			string serviceName,
			uint interestingAccessMask,
			bool useDefaultAccessMask,
			CancellationToken cancellationToken)
		{
			var serviceSpec = new RegistryPathSpec(
				basePath.RootKey,
				basePath.RootName,
				CombineSubkeyPath(basePath.SubkeyPath, serviceName));

			using var serviceKey = OpenRegistryKey(
				client,
				serviceSpec,
				RegistryAccessRights.QueryValue,
				cancellationToken);

			if (!TryReadSecurityDescriptor(smb, client, serviceSpec, cancellationToken, out var descriptor, out var windowsDescriptor))
				return;

			if (descriptor != null)
			{
				if (descriptor.Dacl == null || descriptor.Dacl.Entries.Count == 0)
					return;

				foreach (var ace in descriptor.Dacl.Entries)
				{
					if (!TryGetAceInfo(ace, out var trustee, out var accessMask))
						continue;

					if (!IsAccessMaskInteresting(accessMask, interestingAccessMask, useDefaultAccessMask))
						continue;

					var wellKnownSid = trustee.AsWellKnownSid();
					if (!this.IncludeUninteresting.IsPresent && UninterestingSids.Contains(wellKnownSid))
						continue;
					if (this.IgnoreServiceSids.IsPresent && IsServiceSid(trustee))
						continue;

					var accessRights = BuildAccessRights(accessMask);
					this.WriteObject(new TboRegWeakServiceInfo(
						this.ServerName,
						serviceName,
						serviceSpec.KeyPath,
						trustee.ToString(),
						wellKnownSid,
						ace.AceType,
						accessMask,
						FormatAccessMask(accessMask),
						accessRights,
						(ServiceAccessRights)accessMask,
						(StandardAccessRights)accessMask));
				}

				return;
			}

			if (!OperatingSystem.IsWindows() || windowsDescriptor?.DiscretionaryAcl == null || windowsDescriptor.DiscretionaryAcl.Count == 0)
				return;

			foreach (GenericAce ace in windowsDescriptor.DiscretionaryAcl)
			{
				if (!TryGetWindowsAceInfo(ace, out var trustee, out var accessMask, out var aceType))
					continue;

				if (!IsAccessMaskInteresting(accessMask, interestingAccessMask, useDefaultAccessMask))
					continue;

				var wellKnownSid = trustee.AsWellKnownSid();
				if (!this.IncludeUninteresting.IsPresent && UninterestingSids.Contains(wellKnownSid))
					continue;
				if (this.IgnoreServiceSids.IsPresent && IsServiceSid(trustee))
					continue;

				var accessRights = BuildAccessRights(accessMask);
				this.WriteObject(new TboRegWeakServiceInfo(
					this.ServerName,
					serviceName,
					serviceSpec.KeyPath,
					trustee.ToString(),
					wellKnownSid,
					aceType,
					accessMask,
					FormatAccessMask(accessMask),
					accessRights,
					(ServiceAccessRights)accessMask,
					(StandardAccessRights)accessMask));
			}
		}

		private static bool TryGetWindowsAceInfo(
			GenericAce ace,
			out SecurityIdentifier trustee,
			out uint accessMask,
			out AccessControlEntryType aceType)
		{
			trustee = null!;
			accessMask = 0;
			aceType = AccessControlEntryType.AccessAllowed;

			if (ace is not KnownAce known)
				return false;

			if (ace.AceType is not (AceType.AccessAllowed
				or AceType.AccessAllowedObject
				or AceType.AccessAllowedCallback
				or AceType.AccessAllowedCallbackObject))
			{
				return false;
			}

			aceType = ace.AceType switch
			{
				AceType.AccessAllowed => AccessControlEntryType.AccessAllowed,
				AceType.AccessAllowedObject => AccessControlEntryType.AccessAllowedObject,
				AceType.AccessAllowedCallback => AccessControlEntryType.AccessAllowedCallback,
				AceType.AccessAllowedCallbackObject => AccessControlEntryType.AccessAllowedCallbackObject,
				_ => AccessControlEntryType.AccessAllowed,
			};

			var sidValue = known.SecurityIdentifier?.Value;
			if (string.IsNullOrWhiteSpace(sidValue))
				return false;

			trustee = SecurityIdentifier.Parse(sidValue);
			accessMask = unchecked((uint)known.AccessMask);
			return true;
		}

		private static bool TryGetAceInfo(
			AccessControlEntry ace,
			out SecurityIdentifier trustee,
			out uint accessMask)
		{
			trustee = null!;
			accessMask = 0;

			if (ace.AceType is not (AccessControlEntryType.AccessAllowed
				or AccessControlEntryType.AccessAllowedObject
				or AccessControlEntryType.AccessAllowedCallback
				or AccessControlEntryType.AccessAllowedCallbackObject))
			{
				return false;
			}

			switch (ace)
			{
				case SimpleAce simple:
					trustee = simple.Trustee;
					accessMask = simple.AccessMask;
					return true;
				case Titanis.Winterop.Security.ObjectAce obj:
					trustee = obj.Trustee;
					accessMask = obj.AccessMask;
					return true;
				case CallbackAce callback:
					trustee = callback.Trustee;
					accessMask = callback.AccessMask;
					return true;
				case CallbackObjectAce callbackObject:
					trustee = callbackObject.Trustee;
					accessMask = callbackObject.AccessMask;
					return true;
				default:
					return false;
			}
		}

		private bool TryReadSecurityDescriptor(
			ISmbProviderInfo smb,
			IRegistryClient client,
			RegistryPathSpec serviceSpec,
			CancellationToken cancellationToken,
			out SecurityDescriptor? descriptor,
			out RawSecurityDescriptor? windowsDescriptor)
		{
			descriptor = null;
			windowsDescriptor = null;

			try
			{
				var securitySpec = new RegistryPathSpec(
					serviceSpec.RootKey,
					serviceSpec.RootName,
					CombineSubkeyPath(serviceSpec.SubkeyPath, SecuritySubkeyName));

				using var securityKey = OpenRegistryKey(client, securitySpec, RegistryAccessRights.QueryValue, cancellationToken);
				var valueInfo = securityKey.GetValue(SecurityValueName, cancellationToken).GetAwaiter().GetResult();
				var sdBytes = valueInfo.Bytes;
				if (sdBytes == null && valueInfo.TypedValue is byte[] typedBytes)
					sdBytes = typedBytes;

				if (sdBytes == null || sdBytes.Length == 0)
					return false;

				try
				{
					descriptor = TBOSD.FromRegistryBinary(sdBytes);
				}
				catch (ArgumentException) when (OperatingSystem.IsWindows())
				{
					// Some service SDs (notably those containing custom SACL ACEs) are valid Windows SDs but
					// aren't currently understood by Titanis.Winterop.Security.SecurityDescriptor.
					// Fallback to the OS-backed RawSecurityDescriptor for weak-service triage.
					windowsDescriptor = TBOSD.FromRegistryBinaryAsWindows(sdBytes);
				}

				return true;
			}
			catch (Win32Exception ex) when (IsMissingKey(ex))
			{
				return false;
			}
			catch (Exception ex)
			{
				this.LogException(smb, $"Find-TBORegWeakServices failed to read security descriptor for '{serviceSpec.KeyPath}'", ex);
				this.LogWarning(smb, $"Find-TBORegWeakServices failed to read security descriptor for '{serviceSpec.KeyPath}': {ex.Message}");
				return false;
			}
		}

		private static bool IsMissingKey(Win32Exception ex)
		{
			return ex.NativeErrorCode is (int)Win32ErrorCode.ERROR_FILE_NOT_FOUND
				or (int)Win32ErrorCode.ERROR_PATH_NOT_FOUND
				or (int)Win32ErrorCode.ERROR_BAD_PATHNAME;
		}

		private static string CombineSubkeyPath(string? basePath, string childName)
		{
			if (string.IsNullOrEmpty(basePath))
				return childName;
			if (string.IsNullOrEmpty(childName))
				return basePath;
			return $"{basePath}\\{childName}";
		}

		private uint ResolveAccessMask()
		{
			return this.AccessMask ?? DefaultInterestingAccessMask;
		}

		private static bool IsAccessMaskInteresting(uint accessMask, uint interestingAccessMask, bool useDefaultAccessMask)
		{
			if (!useDefaultAccessMask)
				return (accessMask & interestingAccessMask) != 0;

			if ((accessMask & (uint)ServiceAccessRights.AllRights) == (uint)ServiceAccessRights.AllRights)
				return true;
			if ((accessMask & (uint)ServiceAccessRights.ChangeConfig) != 0)
				return true;
			if ((accessMask & (uint)StandardAccessRights.WriteDac) != 0)
				return true;
			if ((accessMask & (uint)StandardAccessRights.WriteOwner) != 0)
				return true;
			if ((accessMask & GenericWriteMask) != 0)
				return true;

			return false;
		}

		private static bool IsServiceSid(SecurityIdentifier trustee)
		{
			if (trustee.IdentifierAuthority != SecurityIdentifierAuthority.NtAuthority)
				return false;
			if (trustee.SubauthorityCount == 0)
				return false;
			return trustee.GetSubauthority(0) == 80;
		}

		private static IReadOnlyList<string> BuildAccessRights(uint accessMask)
		{
			var rights = new List<string>();

			if ((accessMask & (uint)ServiceAccessRights.AllRights) == (uint)ServiceAccessRights.AllRights)
				rights.Add("SERVICE_ALL_ACCESS");
			if ((accessMask & (uint)ServiceAccessRights.QueryConfig) != 0)
				rights.Add("SERVICE_QUERY_CONFIG");
			if ((accessMask & (uint)ServiceAccessRights.ChangeConfig) != 0)
				rights.Add("SERVICE_CHANGE_CONFIG");
			if ((accessMask & (uint)ServiceAccessRights.QueryStatus) != 0)
				rights.Add("SERVICE_QUERY_STATUS");
			if ((accessMask & (uint)ServiceAccessRights.EnumerateDependents) != 0)
				rights.Add("SERVICE_ENUMERATE_DEPENDENTS");
			if ((accessMask & (uint)ServiceAccessRights.Start) != 0)
				rights.Add("SERVICE_START");
			if ((accessMask & (uint)ServiceAccessRights.Stop) != 0)
				rights.Add("SERVICE_STOP");
			if ((accessMask & (uint)ServiceAccessRights.PauseContinue) != 0)
				rights.Add("SERVICE_PAUSE_CONTINUE");
			if ((accessMask & (uint)ServiceAccessRights.Interrogate) != 0)
				rights.Add("SERVICE_INTERROGATE");
			if ((accessMask & (uint)ServiceAccessRights.UserDefinedControl) != 0)
				rights.Add("SERVICE_USER_DEFINED_CONTROL");

			if ((accessMask & (uint)StandardAccessRights.Delete) != 0)
				rights.Add("DELETE");
			if ((accessMask & (uint)StandardAccessRights.ReadControl) != 0)
				rights.Add("READ_CONTROL");
			if ((accessMask & (uint)StandardAccessRights.WriteDac) != 0)
				rights.Add("WRITE_DAC");
			if ((accessMask & (uint)StandardAccessRights.WriteOwner) != 0)
				rights.Add("WRITE_OWNER");
			if ((accessMask & (uint)StandardAccessRights.Synchronize) != 0)
				rights.Add("SYNCHRONIZE");
			if ((accessMask & (uint)SpecialAccessRights.AccessSystemSecurity) != 0)
				rights.Add("ACCESS_SYSTEM_SECURITY");
			if ((accessMask & (uint)SpecialAccessRights.MaxAllowed) != 0)
				rights.Add("MAXIMUM_ALLOWED");

			if ((accessMask & GenericAllMask) != 0)
				rights.Add("GENERIC_ALL");
			if ((accessMask & GenericExecuteMask) != 0)
				rights.Add("GENERIC_EXECUTE");
			if ((accessMask & GenericWriteMask) != 0)
				rights.Add("GENERIC_WRITE");
			if ((accessMask & GenericReadMask) != 0)
				rights.Add("GENERIC_READ");

			return rights;
		}

		private static string FormatAccessMask(uint accessMask)
		{
			return string.Format(CultureInfo.InvariantCulture, "0x{0:X8}", accessMask);
		}
	}
}
