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

	internal enum ServiceTriggerDataType
	{
		Binary = 1,
		String = 2,
		Level = 3,
		KeywordAny = 4,
		KeywordAll = 5
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
		public TboRegServiceFailureActionsInfo? FailureActionsInfo { get; init; }
		public IReadOnlyList<TboRegServiceTriggerInfo>? TriggerInfo { get; init; }
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

	public sealed class TboRegServiceFailureActionsInfo
	{
		public uint ResetPeriodSeconds { get; init; }
		public string? RebootMessage { get; init; }
		public string? Command { get; init; }
		public IReadOnlyList<TboRegServiceFailureActionInfo> Actions { get; init; } = Array.Empty<TboRegServiceFailureActionInfo>();
	}

	public sealed class TboRegServiceFailureActionInfo
	{
		public string ActionType { get; init; } = string.Empty;
		public uint DelayMs { get; init; }
	}

	public sealed class TboRegServiceTriggerInfo
	{
		public string KeyName { get; init; } = string.Empty;
		public string? KeyPath { get; init; }
		public string? TriggerType { get; init; }
		public string? Action { get; init; }
		public Guid? Subtype { get; init; }
		public string? SubtypeName { get; init; }
		public IReadOnlyList<TboRegServiceTriggerDataItem>? DataItems { get; init; }
		public IReadOnlyList<TboRegServiceTriggerValueInfo>? Values { get; init; }
	}

	public sealed class TboRegServiceTriggerDataItem
	{
		public int Index { get; init; }
		public string? DataType { get; init; }
		public object? Data { get; init; }
		public byte[]? DataBytes { get; init; }
	}

	public sealed class TboRegServiceTriggerValueInfo
	{
		public string Name { get; init; } = string.Empty;
		public RegistryValueType ValueType { get; init; }
		public byte[]? Bytes { get; init; }
		public object? Value { get; init; }
	}

	[Cmdlet(VerbsCommon.Get, "TBORegServiceDetails")]
	[OutputType(typeof(TboRegServiceDetailsInfo))]
	public sealed class GetTBORegServiceDetails : ServiceRegistryCmdletBase
	{
		private const string SecretsPath = @"HKLM\SECURITY\Policy\Secrets";
		private const string ServiceSecretPrefix = "_SC_";
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

				var subkeys = CollectServiceSubkeys(
					smb,
					servicesKey,
					keyInfo,
					parsedPath,
					cancellationToken,
					"Get-TBORegServiceDetails");
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
			IRegistryClient client,
			RegistryPathSpec servicesPath,
			IRegistryKey servicesKey,
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

			var subkeys = CollectServiceSubkeys(
				smb,
				servicesKey,
				servicesInfo,
				servicesPath,
				cancellationToken,
				"Get-TBORegServiceDetails");
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
				this.LogWarning(smb, $"No service keys matched pattern(s): {string.Join(", ", wildcardInputs)}.");
		}


		private bool TryWriteServiceDetails(
			ISmbProviderInfo smb,
			IRegistryClient client,
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
					this.LogWarning(smb, $"Get-TBORegServiceDetails failed to read service '{serviceName}': {retryEx.Message}");
				}
				catch (Exception retryEx)
				{
					this.LogException(smb, $"Get-TBORegServiceDetails failed to read service '{serviceName}'", retryEx);
					this.LogWarning(smb, $"Get-TBORegServiceDetails failed to read service '{serviceName}': {retryEx.Message}");
				}
			}
			catch (Win32Exception ex) when (IsMissingKey(ex))
			{
				if (warnOnMissing)
					this.LogWarning(smb, $"Service key not found: {basePath.KeyPath}\\{serviceName}");
			}
			catch (Exception ex)
			{
				this.LogException(smb, $"Get-TBORegServiceDetails failed to read service '{serviceName}'", ex);
				this.LogWarning(smb, $"Get-TBORegServiceDetails failed to read service '{serviceName}': {ex.Message}");
			}

			return false;
		}

		private void WriteServiceDetails(
			ISmbProviderInfo smb,
			IRegistryClient client,
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
			var triggerInfo = TryReadTriggerInfo(smb, client, serviceSpec, cancellationToken);

			var imagePath = TryGetString(values, "ImagePath");
			var objectName = TryGetString(values, "ObjectName");
			var displayName = TryGetString(values, "DisplayName");

			var start = FormatEnum<ServiceStartType>(TryGetDword(values, "Start"));
			var type = FormatEnum<ServiceTypes>(TryGetDword(values, "Type"));
			var errorControl = FormatEnum<ServiceErrorControl>(TryGetDword(values, "ErrorControl"));
			var requiredPrivileges = TryGetStringArray(values, "RequiredPrivileges");
			var failureActions = TryGetBytes(values, "FailureActions");
			var failureCommand = TryGetString(values, "FailureCommand");
			var failureActionsInfo = TryParseFailureActions(failureActions, failureCommand);

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

			if (failureActionsInfo != null
				&& failureActions != null
				&& failureActionsInfo.Actions?.Any(action => string.Equals(action.ActionType, nameof(ServiceFailureActionType.RunCommand), StringComparison.OrdinalIgnoreCase)) == true
				&& string.IsNullOrWhiteSpace(failureActionsInfo.Command))
			{
				if (TryParseFailureActionsHeader(failureActions, out var header))
				{
					this.LogVerbose(smb, 
						$"FailureActions header for {serviceName}: length={failureActions.Length}, resetPeriod={header.ResetPeriodSeconds}, " +
						$"rebootMsgOffset={header.RebootMsgOffset}, commandOffset={header.CommandOffset}, actionsOffset={header.ActionsOffset}, actionCount={header.ActionCount}.");
				}

				var candidates = CollectFailureActionsCandidates(failureActions, 12);
				if (candidates.Count == 0)
				{
					this.LogVerbose(smb, $"FailureActions string candidates for {serviceName}: none found.");
				}
				else
				{
					foreach (var candidate in candidates)
					{
						var value = candidate.Value.Length > 120
							? candidate.Value.Substring(0, 120) + "..."
							: candidate.Value;
						this.LogVerbose(smb, $"FailureActions candidate [{candidate.Encoding}] @0x{candidate.Offset:X}: {value}");
					}
				}
			}

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
				FailureActionsInfo = failureActionsInfo,
				TriggerInfo = triggerInfo,
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
			IRegistryClient client,
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
				this.LogException(smb, $"Get-TBORegServiceDetails failed to read secret '{secretSpec.KeyPath}'", ex);
				this.LogWarning(smb, $"Get-TBORegServiceDetails failed to read service secret '{secretSpec.KeyPath}': {ex.Message}");
				return null;
			}
		}

		private void TryReadSecurityDescriptor(
			ISmbProviderInfo smb,
			IRegistryClient client,
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

				try
				{
					sd = TBOSD.FromRegistryBinary(sdBytes);
				}
				catch (ArgumentException) when (OperatingSystem.IsWindows())
				{
					// Some service security descriptors are valid Windows SDs but include ACE types
					// not currently supported by Titanis.Winterop.Security.SecurityDescriptor.
					sd = TBOSD.FromRegistryBinaryAsWindows(sdBytes);
				}
			}
			catch (Win32Exception ex) when (IsMissingKey(ex))
			{
			}
			catch (Exception ex)
			{
				this.LogException(smb, $"Get-TBORegServiceDetails failed to read security descriptor for '{serviceSpec.KeyPath}'", ex);
				this.LogWarning(smb, $"Get-TBORegServiceDetails failed to read security descriptor for '{serviceSpec.KeyPath}': {ex.Message}");
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
				try
				{
					return TBOSD.FromRegistryBinary(value);
				}
				catch (ArgumentException) when (OperatingSystem.IsWindows())
				{
					// Same fallback as above, but for security-descriptor-valued subkey fields.
					return TBOSD.FromRegistryBinaryAsWindows(value);
				}
			}
			catch (Exception ex)
			{
				this.LogException(smb, $"Get-TBORegServiceDetails failed to parse {valueName} on '{keyPath}'", ex);
				this.LogWarning(smb, $"Get-TBORegServiceDetails failed to parse {valueName} on '{keyPath}': {ex.Message}");
				return null;
			}
		}

		private IReadOnlyList<string>? TryCollectSubkeyNames(
			ISmbProviderInfo smb,
			IRegistryKey key,
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
				this.LogException(smb, "Get-TBORegServiceDetails failed to enumerate subkeys for a service", ex);
				return null;
			}
		}

		private Dictionary<string, RegistryValueInfo>? TryLoadSubkeyValues(
			ISmbProviderInfo smb,
			IRegistryClient client,
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
				this.LogException(smb, $"Get-TBORegServiceDetails failed to read {subkeyName} values for '{serviceSpec.KeyPath}'", ex);
				this.LogWarning(smb, $"Get-TBORegServiceDetails failed to read {subkeyName} values for '{serviceSpec.KeyPath}': {ex.Message}");
				return null;
			}
		}

		private IReadOnlyList<TboRegServiceTriggerInfo>? TryReadTriggerInfo(
			ISmbProviderInfo smb,
			IRegistryClient client,
			RegistryPathSpec serviceSpec,
			CancellationToken cancellationToken)
		{
			var triggerSpec = new RegistryPathSpec(
				serviceSpec.RootKey,
				serviceSpec.RootName,
				CombineSubkeyPath(serviceSpec.SubkeyPath, "TriggerInfo"));

			try
			{
				using var triggerKey = OpenRegistryKey(
					client,
					triggerSpec,
					RegistryAccessRights.QueryValue | RegistryAccessRights.EnumerateSubkeys,
					cancellationToken);

				var subkeys = CollectSubkeys(triggerKey, cancellationToken)
					.Select(subkey => subkey.KeyName)
					.Where(name => !string.IsNullOrWhiteSpace(name))
					.ToList();

				if (subkeys.Count == 0)
					return null;

				subkeys.Sort(CompareTriggerKeyNames);

				var results = new List<TboRegServiceTriggerInfo>(subkeys.Count);
				foreach (var keyName in subkeys)
				{
					var subkeySpec = new RegistryPathSpec(
						triggerSpec.RootKey,
						triggerSpec.RootName,
						CombineSubkeyPath(triggerSpec.SubkeyPath, keyName));

					using var subkey = OpenRegistryKey(client, subkeySpec, RegistryAccessRights.QueryValue, cancellationToken);
					var values = LoadValues(subkey, cancellationToken);

					var triggerType = FormatEnum<ServiceTriggerType>(TryGetDword(values, "Type"));
					var action = FormatEnum<ServiceTriggerAction>(TryGetDword(values, "Action"));
					var subtype = TryGetGuid(values, "Guid");
					string? subtypeName = null;
					if (subtype.HasValue && TriggerSubtypeNames.TryGetValue(subtype.Value, out var subtypeInfo))
						subtypeName = subtypeInfo;

					var dataItems = TryParseTriggerDataItems(values);
					var valueInfos = values.Count == 0
						? null
						: values.Select(entry => new TboRegServiceTriggerValueInfo
						{
							Name = entry.Key,
							ValueType = entry.Value.ValueType,
							Bytes = entry.Value.Bytes,
							Value = entry.Value.TypedValue
						}).ToList();

					results.Add(new TboRegServiceTriggerInfo
					{
						KeyName = keyName,
						KeyPath = subkeySpec.KeyPath,
						TriggerType = triggerType,
						Action = action,
						Subtype = subtype,
						SubtypeName = subtypeName,
						DataItems = dataItems,
						Values = valueInfos
					});
				}

				return results;
			}
			catch (Win32Exception ex) when (IsMissingKey(ex))
			{
				return null;
			}
			catch (Exception ex)
			{
				this.LogException(smb, $"Get-TBORegServiceDetails failed to read TriggerInfo for '{serviceSpec.KeyPath}'", ex);
				this.LogWarning(smb, $"Get-TBORegServiceDetails failed to read TriggerInfo for '{serviceSpec.KeyPath}': {ex.Message}");
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

		private static int CompareTriggerKeyNames(string? left, string? right)
		{
			if (string.IsNullOrEmpty(left))
				return string.IsNullOrEmpty(right) ? 0 : 1;
			if (string.IsNullOrEmpty(right))
				return -1;

			var leftIsNumeric = TryParseTriggerIndex(left, out var leftIndex);
			var rightIsNumeric = TryParseTriggerIndex(right, out var rightIndex);

			if (leftIsNumeric && rightIsNumeric)
				return leftIndex.CompareTo(rightIndex);
			if (leftIsNumeric)
				return -1;
			if (rightIsNumeric)
				return 1;

			return string.Compare(left, right, StringComparison.OrdinalIgnoreCase);
		}

		private static bool TryParseTriggerIndex(string value, out int index)
		{
			return int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out index);
		}

		private static bool IsMissingKey(Win32Exception ex)
		{
			return ex.NativeErrorCode is (int)Win32ErrorCode.ERROR_FILE_NOT_FOUND
				or (int)Win32ErrorCode.ERROR_PATH_NOT_FOUND
				or (int)Win32ErrorCode.ERROR_BAD_PATHNAME;
		}

		private static Dictionary<string, RegistryValueInfo> LoadValues(IRegistryKey key, CancellationToken cancellationToken)
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
			IRegistryKey key,
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
				"FailureCommand",
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

		private static Guid? TryGetGuid(Dictionary<string, RegistryValueInfo>? values, string name)
		{
			if (!TryGetValue(values, name, out var info))
				return null;

			if (info.TypedValue is Guid typedGuid)
				return typedGuid;

			if (info.TypedValue is string typedString && Guid.TryParse(typedString, out var parsedGuid))
				return parsedGuid;

			if (info.Bytes is { Length: >= 16 } bytes)
				return new Guid(bytes.AsSpan(0, 16));

			return null;
		}

		private static TboRegServiceFailureActionsInfo? TryParseFailureActions(byte[]? bytes, string? fallbackCommand)
		{
			if (bytes is not { Length: >= 20 })
				return null;

			try
			{
				uint resetPeriod = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(0, 4));
				uint rebootMsgOffset = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(4, 4));
				uint commandOffset = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(8, 4));
				uint actionCount = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(12, 4));
				uint actionsOffset = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(16, 4));

				var rebootMsg = ReadServiceString(bytes, rebootMsgOffset);
				var command = ReadServiceString(bytes, commandOffset);
				if (!LooksLikeCommand(command))
					command = FindCommandCandidate(bytes);

				var actions = new List<TboRegServiceFailureActionInfo>();
				bool hasRunCommand = false;
				if (actionCount > 0 && actionsOffset < bytes.Length)
				{
					ulong maxActionBytes = (ulong)actionCount * 8;
					if (actionsOffset + maxActionBytes <= (ulong)bytes.Length)
					{
						var actionSpan = bytes.AsSpan((int)actionsOffset, (int)maxActionBytes);
						for (int i = 0; i < (int)actionCount; i++)
						{
							var offset = i * 8;
							int actionType = BinaryPrimitives.ReadInt32LittleEndian(actionSpan.Slice(offset, 4));
							uint delayMs = BinaryPrimitives.ReadUInt32LittleEndian(actionSpan.Slice(offset + 4, 4));
							if (actionType == (int)ServiceFailureActionType.RunCommand)
								hasRunCommand = true;
							actions.Add(new TboRegServiceFailureActionInfo
							{
								ActionType = FormatFailureActionType(actionType),
								DelayMs = delayMs
							});
						}
					}
				}

				if (hasRunCommand && !LooksLikeCommand(command))
				{
					if (!string.IsNullOrWhiteSpace(fallbackCommand))
						command = fallbackCommand;
					else
						command = null;
				}

				return new TboRegServiceFailureActionsInfo
				{
					ResetPeriodSeconds = resetPeriod,
					RebootMessage = rebootMsg,
					Command = command,
					Actions = actions
				};
			}
			catch
			{
				return null;
			}
		}

		private static string? ReadServiceString(byte[] bytes, uint offset)
		{
			if (offset == 0 || offset >= bytes.Length)
				return null;

			var utf16 = TryDecodeUtf16Z(bytes, (int)offset);
			if (IsLikelyValidServiceString(utf16))
				return utf16;

			var ansi = ReadAnsiZ(bytes, (int)offset);
			if (IsLikelyValidServiceString(ansi))
				return ansi;

			var doubled = offset * 2;
			if (doubled > 0 && doubled < bytes.Length)
			{
				utf16 = TryDecodeUtf16Z(bytes, (int)doubled);
				if (IsLikelyValidServiceString(utf16))
					return utf16;

				ansi = ReadAnsiZ(bytes, (int)doubled);
				if (IsLikelyValidServiceString(ansi))
					return ansi;
			}

			return utf16 ?? ansi;
		}

		private static string? TryDecodeUtf16Z(byte[] bytes, int offset)
		{
			if (offset < 0 || offset + 1 >= bytes.Length)
				return null;

			if (!LooksLikeUtf16(bytes, offset))
				return null;

			int end = -1;
			for (int i = offset; i + 1 < bytes.Length; i += 2)
			{
				if (bytes[i] == 0 && bytes[i + 1] == 0)
				{
					end = i;
					break;
				}
			}

			int length = (end >= offset) ? end - offset : bytes.Length - offset;
			length -= length % 2;
			if (length <= 0)
				return null;

			return Encoding.Unicode.GetString(bytes, offset, length);
		}

		private static string? ReadAnsiZ(byte[] bytes, int offset)
		{
			if (offset < 0 || offset >= bytes.Length)
				return null;

			int end = -1;
			for (int i = offset; i < bytes.Length; i++)
			{
				if (bytes[i] == 0)
				{
					end = i;
					break;
				}
			}

			int length = (end >= offset) ? end - offset : bytes.Length - offset;
			if (length <= 0)
				return null;

			return Encoding.ASCII.GetString(bytes, offset, length);
		}

		private static bool LooksLikeUtf16(byte[] bytes, int offset)
		{
			int pairs = Math.Min((bytes.Length - offset) / 2, 64);
			if (pairs == 0)
				return false;

			int zeroHigh = 0;
			for (int i = 0; i < pairs; i++)
			{
				if (bytes[offset + i * 2 + 1] == 0)
					zeroHigh++;
			}

			return zeroHigh >= pairs * 0.6;
		}

		private static bool IsLikelyValidServiceString(string? value)
		{
			if (string.IsNullOrWhiteSpace(value))
				return false;

			if (value.Length == 1 && !char.IsLetterOrDigit(value[0]) && !IsLikelyPathChar(value[0]))
				return false;

			return true;
		}

		private static bool LooksLikeCommand(string? value)
		{
			if (string.IsNullOrWhiteSpace(value))
				return false;

			return value.Contains(":\\", StringComparison.OrdinalIgnoreCase)
				|| value.Contains("\\\\", StringComparison.OrdinalIgnoreCase)
				|| value.Contains(".exe", StringComparison.OrdinalIgnoreCase)
				|| value.Contains(".cmd", StringComparison.OrdinalIgnoreCase)
				|| value.Contains(".bat", StringComparison.OrdinalIgnoreCase);
		}

		private static string? FindCommandCandidate(byte[] bytes)
		{
			string? best = null;
			foreach (var candidate in EnumerateUtf16ZStrings(bytes))
			{
				if (LooksLikeCommand(candidate))
					return candidate;

				if (best == null && IsLikelyValidServiceString(candidate))
					best = candidate;
			}

			foreach (var candidate in EnumerateAnsiZStrings(bytes))
			{
				if (LooksLikeCommand(candidate))
					return candidate;

				if (best == null && IsLikelyValidServiceString(candidate))
					best = candidate;
			}

			return best;
		}

		private static bool TryParseFailureActionsHeader(byte[] bytes, out FailureActionsHeader header)
		{
			header = default;
			if (bytes.Length < 20)
				return false;

			header = new FailureActionsHeader(
				BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(0, 4)),
				BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(4, 4)),
				BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(8, 4)),
				BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(12, 4)),
				BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(16, 4)));
			return true;
		}

		private static IReadOnlyList<FailureActionStringCandidate> CollectFailureActionsCandidates(byte[] bytes, int maxCount)
		{
			var results = new List<FailureActionStringCandidate>();
			var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

			void AddCandidate(int offset, string encoding, string value)
			{
				if (results.Count >= maxCount)
					return;
				if (string.IsNullOrWhiteSpace(value))
					return;
				if (!seen.Add($"{encoding}:{value}"))
					return;

				results.Add(new FailureActionStringCandidate(offset, encoding, value));
			}

			for (int i = 0; i + 1 < bytes.Length; i++)
			{
				if (bytes[i] == 0 && bytes[i + 1] == 0)
					continue;

				var value = TryDecodeUtf16Z(bytes, i);
				if (!string.IsNullOrWhiteSpace(value))
					AddCandidate(i, "UTF16", value);

				int advance = 1;
				for (int j = i; j + 1 < bytes.Length; j += 2)
				{
					if (bytes[j] == 0 && bytes[j + 1] == 0)
					{
						advance = Math.Max(1, (j - i) + 2);
						break;
					}
				}

				i += Math.Max(advance - 1, 0);
				if (results.Count >= maxCount)
					return results;
			}

			for (int i = 0; i < bytes.Length; i++)
			{
				if (bytes[i] == 0)
					continue;

				var value = ReadAnsiZ(bytes, i);
				if (!string.IsNullOrWhiteSpace(value))
					AddCandidate(i, "ANSI", value);

				int advance = 1;
				for (int j = i; j < bytes.Length; j++)
				{
					if (bytes[j] == 0)
					{
						advance = (j - i) + 1;
						break;
					}
				}

				i += Math.Max(advance - 1, 0);
				if (results.Count >= maxCount)
					return results;
			}

			return results;
		}

		private static IEnumerable<string> EnumerateUtf16ZStrings(byte[] bytes)
		{
			for (int i = 0; i + 1 < bytes.Length; i++)
			{
				if (bytes[i] == 0 && bytes[i + 1] == 0)
					continue;

				var value = TryDecodeUtf16Z(bytes, i);
				if (!string.IsNullOrWhiteSpace(value))
					yield return value;

				int advance = 1;
				for (int j = i; j + 1 < bytes.Length; j += 2)
				{
					if (bytes[j] == 0 && bytes[j + 1] == 0)
					{
						advance = Math.Max(1, (j - i) + 2);
						break;
					}
				}

				i += Math.Max(advance - 1, 0);
			}
		}

		private static IEnumerable<string> EnumerateAnsiZStrings(byte[] bytes)
		{
			for (int i = 0; i < bytes.Length; i++)
			{
				if (bytes[i] == 0)
					continue;

				var value = ReadAnsiZ(bytes, i);
				if (!string.IsNullOrWhiteSpace(value))
					yield return value;

				int advance = 1;
				for (int j = i; j < bytes.Length; j++)
				{
					if (bytes[j] == 0)
					{
						advance = (j - i) + 1;
						break;
					}
				}

				i += Math.Max(advance - 1, 0);
			}
		}

		private static bool IsLikelyPathChar(char value)
			=> value == ':' || value == '\\' || value == '/' || value == '.';

		private readonly record struct FailureActionsHeader(
			uint ResetPeriodSeconds,
			uint RebootMsgOffset,
			uint CommandOffset,
			uint ActionCount,
			uint ActionsOffset);

		private readonly record struct FailureActionStringCandidate(int Offset, string Encoding, string Value);

		private static string FormatFailureActionType(int value)
		{
			if (Enum.IsDefined(typeof(ServiceFailureActionType), value))
				return ((ServiceFailureActionType)value).ToString();

			return value.ToString(CultureInfo.InvariantCulture);
		}

		private static readonly Dictionary<Guid, string> TriggerSubtypeNames = new()
		{
			{ new Guid("1ce20aba-9851-4421-9430-1ddeb766e809"), "DOMAIN_JOIN_GUID" },
			{ new Guid("ddaf516e-58c2-4866-9574-c3b615d42ea1"), "DOMAIN_LEAVE_GUID" },
			{ new Guid("b7569e07-8421-4ee0-ad10-86915afdad09"), "FIREWALL_PORT_OPEN_GUID" },
			{ new Guid("a144ed38-8e12-4de4-9d96-e64740b1a524"), "FIREWALL_PORT_CLOSE_GUID" },
			{ new Guid("659FCAE6-5BDB-4DA9-B1FF-CA2A178D46E0"), "MACHINE_POLICY_PRESENT_GUID" },
			{ new Guid("4f27f2de-14e2-430b-a549-7cd48cbc8245"), "NETWORK_MANAGER_FIRST_IP_ADDRESS_ARRIVAL_GUID" },
			{ new Guid("cc4ba62a-162e-4648-847a-b6bdf993e335"), "NETWORK_MANAGER_LAST_IP_ADDRESS_REMOVAL_GUID" },
			{ new Guid("54FB46C8-F089-464C-B1FD-59D1B62C3B50"), "USER_POLICY_PRESENT_GUID" },
			{ new Guid("1F81D131-3FAC-4537-9E0C-7E7B0C2F4B55"), "NAMED_PIPE_EVENT_GUID" },
			{ new Guid("BC90D167-9470-4139-A9BA-BE0BBBF5B74D"), "RPC_INTERFACE_EVENT_GUID" },
			{ new Guid("2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9"), "CustomSystemStateChange" },
			{ new Guid("0850302A-B344-4FDA-9BE9-90576B8D46F0"), "Bluetooth" },
			{ new Guid("C1E9BC6D-1DAE-421A-9369-CC7FF0D6E359"), "BluetoothMtpEnum" },
			{ new Guid("97f115c8-599a-4153-8894-d2d12899918a"), "LightSensor" },
			{ new Guid("E5323777-F976-4F5B-9B55-B94699C46E44"), "VideoCamera" },
			{ new Guid("24E552D7-6523-47F7-A647-D3465BF1F5CA"), "CameraSensor" },
			{ new Guid("50dd5230-ba8a-11d1-bf5d-0000f805f530"), "SmartcardReader" },
			{ new Guid("199fe037-2b82-40a9-82ac-e1d46c792b99"), "LsaSrv" },
			{ new Guid("D02A9C27-79B8-40D6-9B97-CF3F8B7B5D60"), "Microsoft-Windows-AppIDServiceTrigger" },
			{ new Guid("277c9237-51d8-5c1c-b089-f02c683e5ba7"), "Microsoft-Windows-StartNameRes" },
			{ new Guid("fbcfac3f-8460-419f-8e48-1f0b49cdb85e"), "Microsoft-Windows-NetworkProfileTriggerProvider" },
			{ new Guid("ce20d1c3-a247-4c41-bcb8-3c7f52c8b805"), "Microsoft-Windows-Kernel-Tm-Trigger" },
			{ new Guid("aedd909f-41c6-401a-9e41-dfc33006af5d"), "Microsoft-Windows-Smartcard-Trigger" },
			{ new Guid("f5528ada-be5f-4f14-8aef-a95de7281161"), "Microsoft-Windows-Kernel-Licensing-StartServiceTrigger" },
			{ new Guid("8e6a5303-a4ce-498f-afdb-e03a8a82b077"), "Microsoft-Windows-Ntfs-UBPM" },
			{ new Guid("aa1f73e8-15fd-45d2-abfd-e7f64f78eb11"), "Microsoft-Windows-Kernel-PowerTrigger" },
			{ new Guid("22b6d684-fa63-4578-87c9-effcbe6643c7"), "Microsoft-Windows-WebdavClient-LookupServiceTrigger" },
			{ new Guid("e46eead8-0c54-4489-9898-8fa79d059e0e"), "Microsoft-Windows-Feedback-Service-TriggerProvider" }
		};

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

		private static IReadOnlyList<TboRegServiceTriggerDataItem>? TryParseTriggerDataItems(Dictionary<string, RegistryValueInfo>? values)
		{
			if (values == null || values.Count == 0)
				return null;

			var indices = new SortedSet<int>();
			foreach (var key in values.Keys)
			{
				if (TryGetDataIndex(key, "DataType", out var dataTypeIndex))
				{
					indices.Add(dataTypeIndex);
					continue;
				}

				if (TryGetDataIndex(key, "Data", out var dataIndex))
					indices.Add(dataIndex);
			}

			if (indices.Count == 0)
				return null;

			var items = new List<TboRegServiceTriggerDataItem>(indices.Count);
			foreach (var index in indices)
			{
				var dataType = TryGetDword(values, $"DataType{index}");
				var dataBytes = TryGetBytes(values, $"Data{index}");
				var data = DecodeTriggerData(dataType, dataBytes);

				items.Add(new TboRegServiceTriggerDataItem
				{
					Index = index,
					DataType = FormatEnum<ServiceTriggerDataType>(dataType),
					Data = data,
					DataBytes = dataBytes
				});
			}

			return items;
		}

		private static bool TryGetDataIndex(string key, string prefix, out int index)
		{
			index = default;
			if (!key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
				return false;

			var suffix = key.Substring(prefix.Length);
			return int.TryParse(suffix, NumberStyles.Integer, CultureInfo.InvariantCulture, out index);
		}

		private static object? DecodeTriggerData(uint? dataType, byte[]? data)
		{
			if (data == null || data.Length == 0)
				return null;

			if (dataType == (uint)ServiceTriggerDataType.String)
			{
				var decoded = DecodeMultiString(data);
				if (decoded.Count > 1)
					return decoded;
				if (decoded.Count == 1)
					return decoded[0];

				return TryDecodeUtf16String(data);
			}

			if (dataType == (uint)ServiceTriggerDataType.Level)
				return data[0];

			if (dataType == (uint)ServiceTriggerDataType.KeywordAny
				|| dataType == (uint)ServiceTriggerDataType.KeywordAll)
			{
				return data.Length >= 8
					? BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(0, 8))
					: null;
			}

			return data;
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
