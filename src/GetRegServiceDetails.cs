using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Management.Automation;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Titanis.Msrpc.Msrrp;
using Titanis.Msrpc.Msscmr;
using Titanis.Winterop;
using Titanis.Winterop.Security;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal enum ServiceSidType
	{
		None = 0,
		Unrestricted = 1,
		Restricted = 2
	}

	internal enum ServiceLaunchProtected
	{
		None = 0,
		Windows = 1,
		WindowsLight = 2,
		AntimalwareLight = 3
	}

	public sealed class TboRegServiceDetailsInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string KeyName { get; init; } = string.Empty;
		public string KeyPath { get; init; } = string.Empty;
		public string? ImagePath { get; init; }
		public string? ObjectName { get; init; }
		public string? DisplayName { get; init; }
		public string? Start { get; init; }
		public string? Type { get; init; }
		public string? ErrorControl { get; init; }
		public IReadOnlyList<string>? RequiredPrivileges { get; init; }
		public byte[]? FailureActions { get; init; }
		public string? ServiceSidType { get; init; }
		public string? ServiceSid { get; init; }
		public string? LaunchProtected { get; init; }
		public string? ConfigurationFlags { get; init; }
		public IReadOnlyList<string>? DependOnService { get; init; }
		public IReadOnlyList<string>? DependOnGroup { get; init; }
		public string? SvcHostSplitDisable { get; init; }
		public string? Group { get; init; }
		public string? MitigationFlags { get; init; }
		public string? Description { get; init; }
		public IReadOnlyList<string>? Owners { get; init; }
		public string? Tag { get; init; }
		public string? MofImagePath { get; init; }
		public string? DebugFlags { get; init; }
		public string? Wow64 { get; init; }
		public string? UserServiceFlags { get; init; }
		public string? DelayedAutoStart { get; init; }
		public string? AutoRun { get; init; }
		public string? AutoRunAlwaysDisable { get; init; }
		public string? BootFlags { get; init; }
		public string? SupportedFeatures { get; init; }
		public string? SvcMemSoftLimitInMB { get; init; }
		public string? SvcMemMidLimitInMB { get; init; }
		public string? SvcMemHardLimitInMB { get; init; }
		public string? FailureActionsOnNonCrashFailures { get; init; }
		public string? PreshutdownTimeout { get; init; }
		public string? ServiceDll { get; init; }
		public string? ServiceDllUnloadOnStop { get; init; }
		public string? DisableSubscription { get; init; }
		public string? InactivityShutdownDelay { get; init; }
		public string? RefreshRequired { get; init; }
		public string? ServiceMain { get; init; }
		public string? StateFlags { get; init; }
		public string? AttachWhenLoaded { get; init; }
		public object? HwNClxSecurity { get; init; }
		public byte[]? HwNClxSecurityBytes { get; init; }
		public string? PnpFlags { get; init; }
		public string? HasBootConfig { get; init; }
		public string? TextModeFlags { get; init; }
		public string? RebootMessage { get; init; }
		public string? AllowedProcessName { get; init; }
		public string? DeviceNameTdt { get; init; }
		public string? Silo { get; init; }
		public string? Version { get; init; }
		public string? DeviceCharacteristics { get; init; }
		public string? ServiceIdentity { get; init; }
		public IReadOnlyList<string>? Alias { get; init; }
		public string? ServiceHostSid { get; init; }
		public IReadOnlyList<string>? Subkeys { get; init; }
		public object? SecurityDescriptor { get; init; }
		public byte[]? SecurityDescriptorBytes { get; init; }
		public bool? HasServiceCredential { get; init; }
		public string? ServiceCredentialKeyPath { get; init; }
	}

	[Cmdlet(VerbsCommon.Get, "TBORegServiceDetails")]
	[OutputType(typeof(TboRegServiceDetailsInfo))]
	public sealed class GetTBORegServiceDetails : TboRegCmdlet
	{
		private const string DefaultServicesPath = @"HKLM\SYSTEM\CurrentControlSet\Services";
		private const string SecretsPath = @"HKLM\SECURITY\Policy\Secrets";
		private const string ServiceSecretPrefix = "_SC_";
		private const string SecuritySubkeyName = "Security";
		private const string SecurityValueName = "Security";
		private const string ParametersSubkeyName = "Parameters";

		[Parameter(Position = 1)]
		public string Path { get; set; } = DefaultServicesPath;

		[Parameter(Position = 2, ValueFromPipelineByPropertyName = true)]
		[Alias("ServiceName", "KeyName")]
		public string[]? Name { get; set; }

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			var basePath = string.IsNullOrWhiteSpace(this.Path) ? DefaultServicesPath : this.Path;
			var parsedPath = ParseRegistryPath(basePath, nameof(this.Path));

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
					ProcessRequestedNames(smb, session.Client, parsedPath, servicesKey, keyInfo, requestedNames, cancellationToken);
					return;
				}

				var subkeys = CollectServiceSubkeys(smb, servicesKey, keyInfo, parsedPath, cancellationToken);
				foreach (var subkey in subkeys)
				{
					if (string.IsNullOrWhiteSpace(subkey.KeyName))
						continue;

					TryWriteServiceDetails(
						smb,
						session.Client,
						parsedPath,
						subkey.KeyName,
						cancellationToken,
						warnOnMissing: false);
				}
			});
		}

		private void ProcessRequestedNames(
			ISmbProviderInfo smb,
			RemoteRegistryClient client,
			RegistryPathSpec servicesPath,
			RegistryKey servicesKey,
			RegistryKeyInfo servicesInfo,
			List<string> requestedNames,
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

			var emitted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
			foreach (var name in exactNames)
			{
				if (string.IsNullOrWhiteSpace(name))
					continue;

				if (TryWriteServiceDetails(smb, client, servicesPath, name, cancellationToken, warnOnMissing: true))
					emitted.Add(name);
			}

			if (wildcardPatterns.Count == 0)
				return;

			var subkeys = CollectServiceSubkeys(smb, servicesKey, servicesInfo, servicesPath, cancellationToken);
			var wildcardMatched = false;
			foreach (var subkey in subkeys)
			{
				var keyName = subkey.KeyName;
				if (string.IsNullOrWhiteSpace(keyName) || emitted.Contains(keyName))
					continue;

				if (!MatchesAnyPattern(wildcardPatterns, keyName))
					continue;

				wildcardMatched = true;
				if (TryWriteServiceDetails(smb, client, servicesPath, keyName, cancellationToken, warnOnMissing: false))
					emitted.Add(keyName);
			}

			if (!wildcardMatched)
				this.WriteWarning($"No service keys matched pattern(s): {string.Join(", ", wildcardInputs)}.");
		}

		private List<RegistrySubkeyInfo> CollectServiceSubkeys(
			ISmbProviderInfo smb,
			RegistryKey servicesKey,
			RegistryKeyInfo servicesInfo,
			RegistryPathSpec servicesPath,
			CancellationToken cancellationToken)
		{
			List<RegistrySubkeyInfo> subkeys;
			try
			{
				subkeys = CollectSubkeys(servicesKey, cancellationToken);
			}
			catch (Exception ex)
			{
				smb.LogException("Get-TBORegServiceDetails failed to enumerate service keys", ex);
				throw;
			}

			if (servicesInfo.SubkeyCount > 0 && subkeys.Count != servicesInfo.SubkeyCount)
			{
				this.WriteWarning(
					$"Get-TBORegServiceDetails enumerated {subkeys.Count} of {servicesInfo.SubkeyCount} subkeys under {servicesPath.KeyPath}. Some services may be missing.");
			}

			return subkeys;
		}

		private static List<string> FilterNames(string[]? names)
		{
			if (names == null || names.Length == 0)
				return new List<string>();

			var filtered = new List<string>(names.Length);
			foreach (var name in names)
			{
				if (!string.IsNullOrWhiteSpace(name))
					filtered.Add(name.Trim());
			}

			return filtered;
		}

		private bool TryWriteServiceDetails(
			ISmbProviderInfo smb,
			RemoteRegistryClient client,
			RegistryPathSpec basePath,
			string serviceName,
			CancellationToken cancellationToken,
			bool warnOnMissing)
		{
			try
			{
				WriteServiceDetails(smb, client, basePath, serviceName, cancellationToken);
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
							WriteServiceDetails(smb, session.Client, basePath, serviceName, cancellationToken);
							return true;
						});
				}
				catch (NtstatusException retryEx) when (retryEx.StatusCode == Ntstatus.STATUS_PIPE_BUSY)
				{
					this.WriteWarning($"Get-TBORegServiceDetails failed to read service '{serviceName}': {retryEx.Message}");
				}
				catch (Exception retryEx)
				{
					smb.LogException($"Get-TBORegServiceDetails failed to read service '{serviceName}'", retryEx);
					this.WriteWarning($"Get-TBORegServiceDetails failed to read service '{serviceName}': {retryEx.Message}");
				}
			}
			catch (Win32Exception ex) when (IsMissingKey(ex))
			{
				if (warnOnMissing)
					this.WriteWarning($"Service key not found: {basePath.KeyPath}\\{serviceName}");
			}
			catch (Exception ex)
			{
				smb.LogException($"Get-TBORegServiceDetails failed to read service '{serviceName}'", ex);
				this.WriteWarning($"Get-TBORegServiceDetails failed to read service '{serviceName}': {ex.Message}");
			}

			return false;
		}

		private void WriteServiceDetails(
			ISmbProviderInfo smb,
			RemoteRegistryClient client,
			RegistryPathSpec basePath,
			string serviceName,
			CancellationToken cancellationToken)
		{
			var serviceSpec = new RegistryPathSpec(
				basePath.RootKey,
				basePath.RootName,
				CombineSubkeyPath(basePath.SubkeyPath, serviceName));

			using var serviceKey = OpenRegistryKey(
				client,
				serviceSpec,
				RegistryAccessRights.QueryValue | RegistryAccessRights.EnumerateSubkeys,
				cancellationToken);

			var values = LoadValues(serviceKey, cancellationToken);
			PopulateMissingValues(values, serviceKey, cancellationToken);

			var subkeys = TryCollectSubkeyNames(smb, serviceKey, cancellationToken);
			var parametersValues = TryLoadSubkeyValues(smb, client, serviceSpec, ParametersSubkeyName, cancellationToken);

			var imagePath = TryGetString(values, "ImagePath");
			var objectName = TryGetString(values, "ObjectName");
			var displayName = TryGetString(values, "DisplayName");

			var start = FormatEnum<ServiceStartType>(TryGetDword(values, "Start"));
			var type = FormatEnum<ServiceTypes>(TryGetDword(values, "Type"));
			var errorControl = FormatEnum<ServiceErrorControl>(TryGetDword(values, "ErrorControl"));
			var requiredPrivileges = TryGetStringArray(values, "RequiredPrivileges");
			var failureActions = TryGetBytes(values, "FailureActions");

			var serviceSidType = FormatEnum<ServiceSidType>(TryGetDword(values, "ServiceSidType"));
			var serviceSid = TryComputeServiceSid(serviceName);
			var launchProtected = FormatEnum<ServiceLaunchProtected>(TryGetDword(values, "LaunchProtected"));

			var configurationFlags = FormatDword(TryGetDword(values, "ConfigurationFlags"));
			var dependOnService = TryGetStringArray(values, "DependOnService");
			var dependOnGroup = TryGetStringArray(values, "DependOnGroup");
			var svcHostSplitDisable = FormatBool(TryGetDword(values, "SvcHostSplitDisable"));
			var group = TryGetString(values, "Group");
			var mitigationFlags = FormatDword(TryGetDword(values, "MitigationFlags"));
			var description = TryGetString(values, "Description");
			var owners = TryGetStringArray(values, "Owners");
			var tag = FormatDword(TryGetDword(values, "Tag"));
			var mofImagePath = TryGetString(values, "MofImagePath");
			var debugFlags = FormatDword(TryGetDword(values, "DebugFlags"));
			var wow64 = FormatBool(TryGetDword(values, "WOW64"));
			var userServiceFlags = FormatDword(TryGetDword(values, "UserServiceFlags"));
			var delayedAutoStart = FormatBool(TryGetDword(values, "DelayedAutoStart"));
			var autoRun = FormatBool(TryGetDword(values, "AutoRun"));
			var autoRunAlwaysDisable = FormatBool(TryGetDword(values, "AutoRunAlwaysDisable"));
			var bootFlags = FormatDword(TryGetDword(values, "BootFlags"));
			var supportedFeatures = FormatDword(TryGetDword(values, "SupportedFeatures"));
			var svcMemSoftLimitInMB = FormatDword(TryGetDword(values, "SvcMemSoftLimitInMB"));
			var svcMemMidLimitInMB = FormatDword(TryGetDword(values, "SvcMemMidLimitInMB"));
			var svcMemHardLimitInMB = FormatDword(TryGetDword(values, "SvcMemHardLimitInMB"));
			var failureActionsOnNonCrashFailures = FormatBool(TryGetDword(values, "FailureActionsOnNonCrashFailures"));
			var preshutdownTimeout = FormatDword(TryGetDword(values, "PreshutdownTimeout"));

			var serviceDll = TryGetString(values, "ServiceDll") ?? TryGetString(parametersValues, "ServiceDll");
			var serviceDllUnloadOnStop = FormatBool(
				TryGetDword(values, "ServiceDllUnloadOnStop")
				?? TryGetDword(parametersValues, "ServiceDllUnloadOnStop"));
			var disableSubscription = FormatBool(TryGetDword(parametersValues, "DisableSubscription"));
			var inactivityShutdownDelay = FormatDword(TryGetDword(parametersValues, "InactivityShutdownDelay"));
			var refreshRequired = FormatBool(TryGetDword(parametersValues, "RefreshRequired"));
			var serviceMain = TryGetString(parametersValues, "ServiceMain");

			var stateFlags = FormatDword(TryGetDword(values, "StateFlags"));
			var attachWhenLoaded = FormatBool(TryGetDword(values, "AttachWhenLoaded"));
			var hwNclxSecurityBytes = TryGetBytes(values, "HwNClxSecurity");
			var hwNclxSecurity = TryParseSecurityDescriptorValue(smb, serviceSpec.KeyPath, "HwNClxSecurity", hwNclxSecurityBytes);
			var pnpFlags = FormatDword(TryGetDword(values, "PnpFlags"));
			var hasBootConfig = FormatBool(TryGetDword(values, "HasBootConfig"));
			var textModeFlags = FormatDword(TryGetDword(values, "TextModeFlags"));
			var rebootMessage = TryGetString(values, "RebootMessage");
			var allowedProcessName = TryGetString(values, "AllowedProcessName");
			var deviceNameTdt = TryGetString(values, "DeviceNameTdt");
			var silo = TryGetString(values, "Silo");
			var version = FormatDword(TryGetDword(values, "Version"));
			var deviceCharacteristics = FormatDword(TryGetDword(values, "DeviceCharacteristics"));
			var serviceIdentity = TryGetString(values, "ServiceIdentity");
			var alias = TryGetStringArray(values, "Alias");
			var serviceHostSid = TryGetString(values, "ServiceHostSid");

			byte[]? sdBytes = null;
			object? sd = null;
			TryReadSecurityDescriptor(
				smb,
				client,
				serviceSpec,
				cancellationToken,
				out sdBytes,
				out sd);

			bool? hasServiceCredential = TryGetServiceCredential(
				smb,
				client,
				serviceName,
				cancellationToken,
				out var serviceCredentialKeyPath);

			this.WriteObject(new TboRegServiceDetailsInfo
			{
				ServerName = this.ServerName,
				KeyName = serviceName,
				KeyPath = serviceSpec.KeyPath,
				ImagePath = imagePath,
				ObjectName = objectName,
				DisplayName = displayName,
				Start = start,
				Type = type,
				ErrorControl = errorControl,
				RequiredPrivileges = requiredPrivileges,
				FailureActions = failureActions,
				ServiceSidType = serviceSidType,
				ServiceSid = serviceSid,
				LaunchProtected = launchProtected,
				ConfigurationFlags = configurationFlags,
				DependOnService = dependOnService,
				DependOnGroup = dependOnGroup,
				SvcHostSplitDisable = svcHostSplitDisable,
				Group = group,
				MitigationFlags = mitigationFlags,
				Description = description,
				Owners = owners,
				Tag = tag,
				MofImagePath = mofImagePath,
				DebugFlags = debugFlags,
				Wow64 = wow64,
				UserServiceFlags = userServiceFlags,
				DelayedAutoStart = delayedAutoStart,
				AutoRun = autoRun,
				AutoRunAlwaysDisable = autoRunAlwaysDisable,
				BootFlags = bootFlags,
				SupportedFeatures = supportedFeatures,
				SvcMemSoftLimitInMB = svcMemSoftLimitInMB,
				SvcMemMidLimitInMB = svcMemMidLimitInMB,
				SvcMemHardLimitInMB = svcMemHardLimitInMB,
				FailureActionsOnNonCrashFailures = failureActionsOnNonCrashFailures,
				PreshutdownTimeout = preshutdownTimeout,
				ServiceDll = serviceDll,
				ServiceDllUnloadOnStop = serviceDllUnloadOnStop,
				DisableSubscription = disableSubscription,
				InactivityShutdownDelay = inactivityShutdownDelay,
				RefreshRequired = refreshRequired,
				ServiceMain = serviceMain,
				StateFlags = stateFlags,
				AttachWhenLoaded = attachWhenLoaded,
				HwNClxSecurity = hwNclxSecurity,
				HwNClxSecurityBytes = hwNclxSecurityBytes,
				PnpFlags = pnpFlags,
				HasBootConfig = hasBootConfig,
				TextModeFlags = textModeFlags,
				RebootMessage = rebootMessage,
				AllowedProcessName = allowedProcessName,
				DeviceNameTdt = deviceNameTdt,
				Silo = silo,
				Version = version,
				DeviceCharacteristics = deviceCharacteristics,
				ServiceIdentity = serviceIdentity,
				Alias = alias,
				ServiceHostSid = serviceHostSid,
				Subkeys = subkeys,
				SecurityDescriptor = sd,
				SecurityDescriptorBytes = sdBytes,
				HasServiceCredential = hasServiceCredential,
				ServiceCredentialKeyPath = serviceCredentialKeyPath
			});
		}

		private bool? TryGetServiceCredential(
			ISmbProviderInfo smb,
			RemoteRegistryClient client,
			string serviceName,
			CancellationToken cancellationToken,
			out string? secretKeyPath)
		{
			secretKeyPath = null;
			var rootName = RemoteRegistryClient.GetRootName(RegistryRootKey.LocalMachine);
			var secretSubkey = CombineSubkeyPath(RegistryPathParser.Parse(SecretsPath, nameof(SecretsPath)).SubkeyPath, ServiceSecretPrefix + serviceName);
			var secretSpec = new RegistryPathSpec(RegistryRootKey.LocalMachine, rootName, secretSubkey);
			secretKeyPath = secretSpec.KeyPath;

			try
			{
				using var secretKey = OpenRegistryKey(
					client,
					secretSpec,
					RegistryAccessRights.QueryValue,
					cancellationToken);
				return true;
			}
			catch (Win32Exception ex) when (IsMissingKey(ex))
			{
				return false;
			}
			catch (Exception ex)
			{
				smb.LogException($"Get-TBORegServiceDetails failed to read secret '{secretSpec.KeyPath}'", ex);
				this.WriteWarning($"Get-TBORegServiceDetails failed to read service secret '{secretSpec.KeyPath}': {ex.Message}");
				return null;
			}
		}

		private void TryReadSecurityDescriptor(
			ISmbProviderInfo smb,
			RemoteRegistryClient client,
			RegistryPathSpec serviceSpec,
			CancellationToken cancellationToken,
			out byte[]? sdBytes,
			out object? sd)
		{
			sdBytes = null;
			sd = null;

			try
			{
				var securitySpec = new RegistryPathSpec(
					serviceSpec.RootKey,
					serviceSpec.RootName,
					CombineSubkeyPath(serviceSpec.SubkeyPath, SecuritySubkeyName));

				using var securityKey = OpenRegistryKey(client, securitySpec, RegistryAccessRights.QueryValue, cancellationToken);
				var valueInfo = securityKey.GetValue(SecurityValueName, cancellationToken).GetAwaiter().GetResult();
				sdBytes = valueInfo.Bytes;
				if (sdBytes == null && valueInfo.TypedValue is byte[] typedBytes)
					sdBytes = typedBytes;

				if (sdBytes == null || sdBytes.Length == 0)
					return;

				sd = TBOSD.FromRegistryBinary(sdBytes);
			}
			catch (Win32Exception ex) when (IsMissingKey(ex))
			{
			}
			catch (Exception ex)
			{
				smb.LogException($"Get-TBORegServiceDetails failed to read security descriptor for '{serviceSpec.KeyPath}'", ex);
				this.WriteWarning($"Get-TBORegServiceDetails failed to read security descriptor for '{serviceSpec.KeyPath}': {ex.Message}");
			}
		}

		private object? TryParseSecurityDescriptorValue(
			ISmbProviderInfo smb,
			string keyPath,
			string valueName,
			byte[]? value)
		{
			if (value == null || value.Length == 0)
				return null;

			try
			{
				return TBOSD.FromRegistryBinary(value);
			}
			catch (Exception ex)
			{
				smb.LogException($"Get-TBORegServiceDetails failed to parse {valueName} on '{keyPath}'", ex);
				this.WriteWarning($"Get-TBORegServiceDetails failed to parse {valueName} on '{keyPath}': {ex.Message}");
				return null;
			}
		}

		private static IReadOnlyList<string>? TryCollectSubkeyNames(
			ISmbProviderInfo smb,
			RegistryKey key,
			CancellationToken cancellationToken)
		{
			try
			{
				return CollectSubkeys(key, cancellationToken)
					.Select(subkey => subkey.KeyName)
					.Where(name => !string.IsNullOrWhiteSpace(name))
					.ToArray();
			}
			catch (Exception ex)
			{
				smb.LogException("Get-TBORegServiceDetails failed to enumerate subkeys for a service", ex);
				return null;
			}
		}

		private Dictionary<string, RegistryValueInfo>? TryLoadSubkeyValues(
			ISmbProviderInfo smb,
			RemoteRegistryClient client,
			RegistryPathSpec serviceSpec,
			string subkeyName,
			CancellationToken cancellationToken)
		{
			var subkeySpec = new RegistryPathSpec(
				serviceSpec.RootKey,
				serviceSpec.RootName,
				CombineSubkeyPath(serviceSpec.SubkeyPath, subkeyName));

			try
			{
				using var subkey = OpenRegistryKey(client, subkeySpec, RegistryAccessRights.QueryValue, cancellationToken);
				return LoadValues(subkey, cancellationToken);
			}
			catch (Win32Exception ex) when (IsMissingKey(ex))
			{
				return null;
			}
			catch (Exception ex)
			{
				smb.LogException($"Get-TBORegServiceDetails failed to read {subkeyName} values for '{serviceSpec.KeyPath}'", ex);
				this.WriteWarning($"Get-TBORegServiceDetails failed to read {subkeyName} values for '{serviceSpec.KeyPath}': {ex.Message}");
				return null;
			}
		}

		private static string? FormatEnum<TEnum>(uint? value) where TEnum : struct, Enum
		{
			if (!value.HasValue)
				return null;

			var enumType = typeof(TEnum);
			var underlyingType = Enum.GetUnderlyingType(enumType);
			try
			{
				var converted = Convert.ChangeType(value.Value, underlyingType, CultureInfo.InvariantCulture);
				var formatted = Enum.Format(enumType, converted, "F");
				return $"{formatted} ({value.Value})";
			}
			catch
			{
				return value.Value.ToString(CultureInfo.InvariantCulture);
			}
		}

		private static string? FormatBool(uint? value)
		{
			if (!value.HasValue)
				return null;

			return $"{(value.Value != 0 ? "True" : "False")} ({value.Value})";
		}

		private static string? FormatDword(uint? value)
		{
			return value.HasValue ? value.Value.ToString(CultureInfo.InvariantCulture) : null;
		}

		private static string? TryComputeServiceSid(string serviceName)
		{
			if (string.IsNullOrWhiteSpace(serviceName))
				return null;

			using var sha1 = SHA1.Create();
			var nameBytes = Encoding.Unicode.GetBytes(serviceName.ToUpperInvariant());
			var hash = sha1.ComputeHash(nameBytes);
			if (hash.Length < 20)
				return null;

			uint a0 = BinaryPrimitives.ReadUInt32LittleEndian(hash.AsSpan(0, 4));
			uint a1 = BinaryPrimitives.ReadUInt32LittleEndian(hash.AsSpan(4, 4));
			uint a2 = BinaryPrimitives.ReadUInt32LittleEndian(hash.AsSpan(8, 4));
			uint a3 = BinaryPrimitives.ReadUInt32LittleEndian(hash.AsSpan(12, 4));
			uint a4 = BinaryPrimitives.ReadUInt32LittleEndian(hash.AsSpan(16, 4));

			return $"S-1-5-80-{a0}-{a1}-{a2}-{a3}-{a4}";
		}

		private static bool MatchesAnyPattern(IReadOnlyList<WildcardPattern> patterns, string value)
		{
			foreach (var pattern in patterns)
			{
				if (pattern.IsMatch(value))
					return true;
			}

			return false;
		}

		private static bool IsMissingKey(Win32Exception ex)
		{
			return ex.NativeErrorCode is (int)Win32ErrorCode.ERROR_FILE_NOT_FOUND
				or (int)Win32ErrorCode.ERROR_PATH_NOT_FOUND
				or (int)Win32ErrorCode.ERROR_BAD_PATHNAME;
		}

		private static Dictionary<string, RegistryValueInfo> LoadValues(RegistryKey key, CancellationToken cancellationToken)
		{
			try
			{
				return CollectValues(key, includeData: true, cancellationToken)
					.ToDictionary(value => value.Name, StringComparer.OrdinalIgnoreCase);
			}
			catch (NotSupportedException)
			{
				return CollectValues(key, includeData: false, cancellationToken)
					.ToDictionary(value => value.Name, StringComparer.OrdinalIgnoreCase);
			}
		}

		private static void PopulateMissingValues(
			Dictionary<string, RegistryValueInfo> values,
			RegistryKey key,
			CancellationToken cancellationToken)
		{
			foreach (var name in new[]
			{
				"ImagePath",
				"ObjectName",
				"DisplayName",
				"Start",
				"Type",
				"ErrorControl",
				"RequiredPrivileges",
				"FailureActions",
				"ServiceSidType",
				"LaunchProtected",
				"ConfigurationFlags",
				"DependOnService",
				"DependOnGroup",
				"SvcHostSplitDisable",
				"Group",
				"MitigationFlags",
				"Description",
				"Owners",
				"Tag",
				"MofImagePath",
				"DebugFlags",
				"WOW64",
				"UserServiceFlags",
				"DelayedAutoStart",
				"AutoRun",
				"AutoRunAlwaysDisable",
				"BootFlags",
				"SupportedFeatures",
				"SvcMemSoftLimitInMB",
				"SvcMemMidLimitInMB",
				"SvcMemHardLimitInMB",
				"FailureActionsOnNonCrashFailures",
				"PreshutdownTimeout",
				"ServiceDll",
				"ServiceDllUnloadOnStop",
				"StateFlags",
				"AttachWhenLoaded",
				"HwNClxSecurity",
				"PnpFlags",
				"HasBootConfig",
				"TextModeFlags",
				"RebootMessage",
				"AllowedProcessName",
				"DeviceNameTdt",
				"Silo",
				"Version",
				"DeviceCharacteristics",
				"ServiceIdentity",
				"Alias",
				"ServiceHostSid"
			})
			{
				if (values.ContainsKey(name))
					continue;

				try
				{
					var valueInfo = key.GetValue(name, cancellationToken).GetAwaiter().GetResult();
					values[name] = valueInfo;
				}
				catch (Win32Exception ex) when (IsMissingKey(ex))
				{
				}
			}
		}

		private static bool TryGetValue(Dictionary<string, RegistryValueInfo>? values, string name, out RegistryValueInfo info)
		{
			info = default;
			return values != null && values.TryGetValue(name, out info);
		}

		private static IReadOnlyList<string>? TryGetStringArray(Dictionary<string, RegistryValueInfo>? values, string name)
		{
			if (!TryGetValue(values, name, out var info))
				return null;

			var typed = info.TypedValue;
			if (typed is string[] array)
				return array;
			if (typed is IEnumerable<string> enumerable)
				return enumerable.Where(item => !string.IsNullOrWhiteSpace(item)).ToArray();
			if (typed is string single)
				return SplitMultiString(single);
			if (info.Bytes is { Length: > 0 })
				return DecodeMultiString(info.Bytes);

			return null;
		}

		private static string? TryGetString(Dictionary<string, RegistryValueInfo>? values, string name)
		{
			if (!TryGetValue(values, name, out var info))
				return null;

			var typed = info.TypedValue;
			if (typed != null)
				return Convert.ToString(typed, CultureInfo.InvariantCulture);

			if (info.Bytes is { Length: > 0 }
				&& info.ValueType is RegistryValueType.String or RegistryValueType.ExpandString)
				return TryDecodeUtf16String(info.Bytes);

			return null;
		}

		private static uint? TryGetDword(Dictionary<string, RegistryValueInfo>? values, string name)
		{
			if (!TryGetValue(values, name, out var info))
				return null;

			var typed = info.TypedValue;
			if (typed == null)
				return null;

			try
			{
				return Convert.ToUInt32(typed, CultureInfo.InvariantCulture);
			}
			catch
			{
				return null;
			}
		}

		private static byte[]? TryGetBytes(Dictionary<string, RegistryValueInfo>? values, string name)
		{
			if (!TryGetValue(values, name, out var info))
				return null;

			if (info.TypedValue is byte[] typedBytes)
				return typedBytes;

			if (info.Bytes is { Length: > 0 })
				return info.Bytes;

			return null;
		}

		private static IReadOnlyList<string> SplitMultiString(string value)
		{
			return value.Split('\0', StringSplitOptions.RemoveEmptyEntries);
		}

		private static IReadOnlyList<string> DecodeMultiString(byte[] data)
		{
			var decoded = Encoding.Unicode.GetString(data);
			return decoded.Split('\0', StringSplitOptions.RemoveEmptyEntries);
		}

		private static string? TryDecodeUtf16String(byte[] bytes)
		{
			int length = bytes.Length;
			if ((length % 2) != 0)
				return null;

			if (length >= 2 && bytes[^1] == 0 && bytes[^2] == 0)
				length -= 2;

			try
			{
				return Encoding.Unicode.GetString(bytes, 0, length);
			}
			catch
			{
				return null;
			}
		}

		private static string CombineSubkeyPath(string? basePath, string childName)
		{
			if (string.IsNullOrEmpty(basePath))
				return childName;
			if (string.IsNullOrEmpty(childName))
				return basePath;
			return $"{basePath}\\{childName}";
		}
	}
}
