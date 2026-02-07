using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Text;
using System.Threading;
using System.Xml.Linq;
using Titanis.Msrpc.Msrrp;
using Titanis.Net;
using Titanis.Smb2;
using Titanis.Winterop;
using Titanis.Winterop.Security;
using Smb2AccessRights = Titanis.Smb2.Smb2FileAccessRights;
using Winterop = Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboScheduledTaskDetailsInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string TaskName { get; init; } = string.Empty;
		public string TaskPath { get; init; } = string.Empty;
		public string TaskFilePath { get; init; } = string.Empty;
		public string? TaskId { get; init; }
		public DateTime? FileCreationTime { get; init; }
		public DateTime? FileLastWriteTime { get; init; }
		public DateTime? FileLastChangeTime { get; init; }
		public DateTime? RegistryLastWriteTime { get; init; }
		public string? TaskXml { get; init; }
		public IReadOnlyList<TboScheduledTaskTriggerInfo>? Triggers { get; init; }
		public IReadOnlyList<TboScheduledTaskActionInfo>? Actions { get; init; }
		public TboScheduledTaskPrincipalInfo? Principal { get; init; }
		public TboScheduledTaskSettingsInfo? Settings { get; init; }
		public object? SecurityDescriptor { get; init; }
		public byte[]? SecurityDescriptorBytes { get; init; }
		public object? TaskSecurityDescriptor { get; init; }
		public byte[]? TaskSecurityDescriptorBytes { get; init; }
	}

	public sealed class TboScheduledTaskTriggerInfo
	{
		public string TriggerType { get; init; } = string.Empty;
		public string? Id { get; init; }
		public string? StartBoundary { get; init; }
		public string? EndBoundary { get; init; }
		public bool? Enabled { get; init; }
		public string? Delay { get; init; }
		public string? UserId { get; init; }
		public string? ExecutionTimeLimit { get; init; }
		public string? RandomDelay { get; init; }
		public string? RepetitionInterval { get; init; }
		public string? RepetitionDuration { get; init; }
		public bool? RepetitionStopAtDurationEnd { get; init; }
		public string? Subscription { get; init; }
		public string? StateChange { get; init; }
		public IReadOnlyDictionary<string, string>? Properties { get; init; }
	}

	public sealed class TboScheduledTaskActionInfo
	{
		public string ActionType { get; init; } = string.Empty;
		public string? Context { get; init; }
		public string? Command { get; init; }
		public string? Arguments { get; init; }
		public string? WorkingDirectory { get; init; }
		public string? ClassId { get; init; }
		public string? Data { get; init; }
		public IReadOnlyDictionary<string, string>? Properties { get; init; }
	}

	public sealed class TboScheduledTaskPrincipalInfo
	{
		public string? Id { get; init; }
		public string? UserId { get; init; }
		public string? GroupId { get; init; }
		public string? LogonType { get; init; }
		public string? RunLevel { get; init; }
		public string? DisplayName { get; init; }
	}

	public sealed class TboScheduledTaskSettingsInfo
	{
		public bool? Enabled { get; init; }
		public bool? AllowStartOnDemand { get; init; }
		public bool? DisallowStartIfOnBatteries { get; init; }
		public bool? StopIfGoingOnBatteries { get; init; }
		public bool? Hidden { get; init; }
		public bool? RunOnlyIfIdle { get; init; }
		public bool? WakeToRun { get; init; }
		public bool? StartWhenAvailable { get; init; }
		public bool? RunOnlyIfNetworkAvailable { get; init; }
		public bool? UseUnifiedSchedulingEngine { get; init; }
		public string? ExecutionTimeLimit { get; init; }
		public string? MultipleInstancesPolicy { get; init; }
		public int? Priority { get; init; }
		public string? NetworkProfileName { get; init; }
		public string? IdleDuration { get; init; }
		public string? IdleWaitTimeout { get; init; }
		public bool? StopOnIdleEnd { get; init; }
		public bool? RestartOnIdle { get; init; }
		public string? MaintenancePeriod { get; init; }
		public string? MaintenanceDeadline { get; init; }
		public bool? MaintenanceExclusive { get; init; }
	}
	[Cmdlet(VerbsCommon.Get, "TBOScheduledTaskDetails")]
	[OutputType(typeof(TboScheduledTaskDetailsInfo))]
	public sealed class GetTBOScheduledTaskDetails : ScheduledTaskCmdletBase
	{
		private const string InputParameterSet = "InputObject";
		private const string FilterParameterSet = "Filter";
		private const int DefaultSecurityDescriptorBufferSize = 8192;

		[Parameter(Mandatory = true, ValueFromPipeline = true, ParameterSetName = InputParameterSet)]
		public TboScheduledTaskInfo? InputObject { get; set; }

		[Parameter(Position = 1, ParameterSetName = FilterParameterSet)]
		[Alias("TaskName")]
		public string[]? Name { get; set; }

		[Parameter(Position = 2, ParameterSetName = FilterParameterSet)]
		[Alias("TaskPath")]
		public string[]? Path { get; set; }

		[Parameter]
		public SwitchParameter AsSddl { get; set; }

		[Parameter]
		public SwitchParameter AsWindows { get; set; }

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			if (this.AsSddl.IsPresent && this.AsWindows.IsPresent)
				throw new ArgumentException("Only one of -AsSddl or -AsWindows can be specified.");
			if (this.AsWindows.IsPresent && !OperatingSystem.IsWindows())
				throw new NotSupportedException("AsWindows is only supported on Windows.");

			var format = SecurityDescriptorHelpers.ResolveFormat(this.AsSddl.IsPresent, asBytes: false, this.AsWindows.IsPresent);

			if (this.ParameterSetName == InputParameterSet)
			{
				if (this.InputObject == null)
					return;

				WriteTaskDetails(smb, this.InputObject, format, cancellationToken);
				return;
			}

			var nameFilters = BuildFilters(this.Name, normalizePath: false);
			var pathFilters = BuildFilters(this.Path, normalizePath: true);
			var emitted = 0;

			var taskCache = ReadTaskCacheEntries(smb, cancellationToken, "Get-TBOScheduledTaskDetails", out var pipeBusyCount);

			if (pipeBusyCount > 0)
			{
				this.LogWarning(smb, $"Get-TBOScheduledTaskDetails skipped {pipeBusyCount} TaskCache subkey(s) due to STATUS_PIPE_BUSY. TaskId/RegistryLastWriteTime may be missing for some tasks.");
			}

			var taskFiles = ReadTaskFiles(smb, cancellationToken, "Get-TBOScheduledTaskDetails");

			foreach (var taskFile in taskFiles)
			{
				var relativePath = taskFile.RelativePath;
				var taskName = GetTaskName(relativePath);
				var taskPath = NormalizeTaskPath(relativePath);

				if (!MatchesFilters(nameFilters, taskName))
					continue;
				if (!MatchesFilters(pathFilters, NormalizeRelativePath(relativePath)))
					continue;

				taskCache.TryGetValue(NormalizeRelativePath(relativePath), out var cacheEntry);

				emitted++;
				WriteTaskDetails(
					smb,
					this.ServerName,
					taskName,
					taskPath,
					taskFile.UncPath,
					cacheEntry?.TaskId,
					taskFile.CreationTime,
					taskFile.LastWriteTime,
					taskFile.LastChangeTime,
					cacheEntry?.RegistryLastWriteTime,
					cacheEntry?.TaskSecurityDescriptorBytes,
					format,
					cancellationToken);
			}

			if (emitted == 0 && (nameFilters.Count > 0 || pathFilters.Count > 0))
				this.LogWarning(smb, "Get-TBOScheduledTaskDetails did not match any tasks for the provided filters.");
		}

		private void WriteTaskDetails(ISmbProviderInfo smb, TboScheduledTaskInfo input, SecurityDescriptorOutputFormat format, CancellationToken cancellationToken)
		{
			var serverName = string.IsNullOrWhiteSpace(input.ServerName) ? this.ServerName : input.ServerName;
			var taskName = input.TaskName ?? string.Empty;
			var taskPath = string.IsNullOrWhiteSpace(input.TaskPath)
				? NormalizeTaskPath(input.TaskName)
				: input.TaskPath;
			var taskFilePath = ResolveTaskFilePath(serverName, input.TaskFilePath, taskPath);
			var taskSdBytes = TryReadTaskCacheSecurityDescriptorBytes(smb, taskPath, cancellationToken);

			WriteTaskDetails(
				smb,
				serverName,
				taskName,
				taskPath,
				taskFilePath,
				input.TaskId,
				input.FileCreationTime,
				input.FileLastWriteTime,
				input.FileLastChangeTime,
				input.RegistryLastWriteTime,
				taskSdBytes,
				format,
				cancellationToken);
		}

		private void WriteTaskDetails(
			ISmbProviderInfo smb,
			string serverName,
			string taskName,
			string taskPath,
			UncPath taskFilePath,
			string? taskId,
			DateTime? creationTime,
			DateTime? lastWriteTime,
			DateTime? lastChangeTime,
			DateTime? registryLastWriteTime,
			byte[]? taskSecurityDescriptorBytes,
			SecurityDescriptorOutputFormat format,
			CancellationToken cancellationToken)
		{
			TaskFileDetails? fileDetails = null;
			try
			{
				fileDetails = ReadTaskFile(smb, taskFilePath, format, cancellationToken);
			}
			catch (Exception ex)
			{
				this.LogException(smb, $"Get-TBOScheduledTaskDetails failed to read task '{taskPath}'", ex);
			}

			var xml = fileDetails?.TaskXml;
			TaskXmlDetails parsed = default;
			if (!string.IsNullOrWhiteSpace(xml))
			{
				try
				{
					parsed = ParseTaskXml(xml);
				}
				catch (Exception ex)
				{
					this.LogException(smb, $"Get-TBOScheduledTaskDetails failed to parse XML for '{taskPath}'", ex);
				}
			}

			object? taskSecurityDescriptor = null;
			if (taskSecurityDescriptorBytes != null && taskSecurityDescriptorBytes.Length > 0)
			{
				try
				{
					var sd = TBOSD.FromRegistryBinary(taskSecurityDescriptorBytes);
					taskSecurityDescriptor = SecurityDescriptorHelpers.Format(sd, format);
				}
				catch (Exception ex)
				{
					this.LogException(smb, $"Get-TBOScheduledTaskDetails failed to parse TaskCache security descriptor for '{taskPath}'", ex);
				}
			}

			this.WriteObject(new TboScheduledTaskDetailsInfo
			{
				ServerName = serverName,
				TaskName = taskName,
				TaskPath = taskPath,
				TaskFilePath = taskFilePath.ToString(),
				TaskId = taskId,
				FileCreationTime = fileDetails?.CreationTime ?? creationTime,
				FileLastWriteTime = fileDetails?.LastWriteTime ?? lastWriteTime,
				FileLastChangeTime = fileDetails?.LastChangeTime ?? lastChangeTime,
				RegistryLastWriteTime = registryLastWriteTime,
				TaskXml = xml,
				Triggers = parsed.Triggers,
				Actions = parsed.Actions,
				Principal = parsed.Principal,
				Settings = parsed.Settings,
				SecurityDescriptor = fileDetails?.SecurityDescriptor,
				SecurityDescriptorBytes = fileDetails?.SecurityDescriptorBytes,
				TaskSecurityDescriptor = taskSecurityDescriptor,
				TaskSecurityDescriptorBytes = taskSecurityDescriptorBytes
			});
		}

		private sealed class TaskFileDetails
		{
			public TaskFileDetails(
				string? taskXml,
				DateTime? creationTime,
				DateTime? lastWriteTime,
				DateTime? lastChangeTime,
				object? securityDescriptor,
				byte[]? securityDescriptorBytes)
			{
				this.TaskXml = taskXml;
				this.CreationTime = creationTime;
				this.LastWriteTime = lastWriteTime;
				this.LastChangeTime = lastChangeTime;
				this.SecurityDescriptor = securityDescriptor;
				this.SecurityDescriptorBytes = securityDescriptorBytes;
			}

			public string? TaskXml { get; }
			public DateTime? CreationTime { get; }
			public DateTime? LastWriteTime { get; }
			public DateTime? LastChangeTime { get; }
			public object? SecurityDescriptor { get; }
			public byte[]? SecurityDescriptorBytes { get; }
		}

		private readonly struct TaskXmlDetails
		{
			public TaskXmlDetails(
				IReadOnlyList<TboScheduledTaskTriggerInfo>? triggers,
				IReadOnlyList<TboScheduledTaskActionInfo>? actions,
				TboScheduledTaskPrincipalInfo? principal,
				TboScheduledTaskSettingsInfo? settings)
			{
				this.Triggers = triggers;
				this.Actions = actions;
				this.Principal = principal;
				this.Settings = settings;
			}

			public IReadOnlyList<TboScheduledTaskTriggerInfo>? Triggers { get; }
			public IReadOnlyList<TboScheduledTaskActionInfo>? Actions { get; }
			public TboScheduledTaskPrincipalInfo? Principal { get; }
			public TboScheduledTaskSettingsInfo? Settings { get; }
		}

		private TaskFileDetails ReadTaskFile(
			ISmbProviderInfo smb,
			UncPath taskFilePath,
			SecurityDescriptorOutputFormat format,
			CancellationToken cancellationToken)
		{
			Smb2OpenFile? file = null;
			try
			{
				var createInfo = new Smb2CreateInfo
				{
					CreateDisposition = Smb2CreateDisposition.Open,
					DesiredAccess = (uint)(Smb2AccessRights.ReadData | Smb2AccessRights.ReadAttributes | Smb2AccessRights.ReadControl),
					ShareAccess = Smb2ShareAccess.ReadWriteDelete,
					ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
					CreateOptions = Smb2FileCreateOptions.NonDirectory
						| Smb2FileCreateOptions.SynchronousIoNonalert
						| Smb2FileCreateOptions.OpenForBackupIntent,
					FileAttributes = Winterop.FileAttributes.Normal
				};

				file = (Smb2OpenFile)smb.SmbClient.CreateFileAsync(taskFilePath, createInfo, FileAccess.Read, cancellationToken).GetAwaiter().GetResult();
				var basicInfo = file.GetBasicInfoAsync(cancellationToken).GetAwaiter().GetResult();

				object? securityDescriptor = null;
				byte[]? securityDescriptorBytes = null;
				try
				{
					var descriptor = file.GetSecurityAsync(
						SecurityInfo.Owner | SecurityInfo.Group | SecurityInfo.Dacl,
						DefaultSecurityDescriptorBufferSize,
						cancellationToken).GetAwaiter().GetResult();
					if (descriptor != null)
					{
						securityDescriptorBytes = descriptor.ToByteArray();
						securityDescriptor = SecurityDescriptorHelpers.Format(descriptor, format);
					}
				}
				catch (Exception ex)
				{
					this.LogException(smb, $"Get-TBOScheduledTaskDetails failed to read security descriptor for '{taskFilePath}'", ex);
				}

				string? xml = null;
				try
				{
					using var stream = file.GetStream(false);
					using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
					xml = reader.ReadToEnd();
				}
				catch (Exception ex)
				{
					this.LogException(smb, $"Get-TBOScheduledTaskDetails failed to read task XML for '{taskFilePath}'", ex);
				}

				return new TaskFileDetails(
					xml,
					basicInfo.CreationTime,
					basicInfo.LastWriteTime,
					basicInfo.ChangeTime,
					securityDescriptor,
					securityDescriptorBytes);
			}
			finally
			{
				if (file != null)
					file.CloseAsync(cancellationToken).GetAwaiter().GetResult();
			}
		}
		private static TaskXmlDetails ParseTaskXml(string xml)
		{
			var doc = XDocument.Parse(xml, LoadOptions.None);
			if (doc.Root == null)
				return default;

			var ns = doc.Root.Name.Namespace;
			var principal = ParsePrincipal(doc.Root, ns);
			var settings = ParseSettings(doc.Root, ns);
			var triggers = ParseTriggers(doc.Root, ns);
			var actions = ParseActions(doc.Root, ns);

			return new TaskXmlDetails(triggers, actions, principal, settings);
		}

		private static TboScheduledTaskPrincipalInfo? ParsePrincipal(XElement root, XNamespace ns)
		{
			var principals = root.Element(ns + "Principals");
			var principal = principals?.Elements(ns + "Principal").FirstOrDefault();
			if (principal == null)
				return null;

			return new TboScheduledTaskPrincipalInfo
			{
				Id = principal.Attribute("id")?.Value,
				UserId = GetElementValue(principal, ns + "UserId"),
				GroupId = GetElementValue(principal, ns + "GroupId"),
				LogonType = GetElementValue(principal, ns + "LogonType"),
				RunLevel = GetElementValue(principal, ns + "RunLevel"),
				DisplayName = GetElementValue(principal, ns + "DisplayName")
			};
		}

		private static TboScheduledTaskSettingsInfo? ParseSettings(XElement root, XNamespace ns)
		{
			var settings = root.Element(ns + "Settings");
			if (settings == null)
				return null;

			var idleSettings = settings.Element(ns + "IdleSettings");
			var maintenance = settings.Element(ns + "MaintenanceSettings");
			var networkSettings = settings.Element(ns + "NetworkSettings");

			return new TboScheduledTaskSettingsInfo
			{
				Enabled = TryParseBool(GetElementValue(settings, ns + "Enabled")),
				AllowStartOnDemand = TryParseBool(GetElementValue(settings, ns + "AllowStartOnDemand")),
				DisallowStartIfOnBatteries = TryParseBool(GetElementValue(settings, ns + "DisallowStartIfOnBatteries")),
				StopIfGoingOnBatteries = TryParseBool(GetElementValue(settings, ns + "StopIfGoingOnBatteries")),
				Hidden = TryParseBool(GetElementValue(settings, ns + "Hidden")),
				RunOnlyIfIdle = TryParseBool(GetElementValue(settings, ns + "RunOnlyIfIdle")),
				WakeToRun = TryParseBool(GetElementValue(settings, ns + "WakeToRun")),
				StartWhenAvailable = TryParseBool(GetElementValue(settings, ns + "StartWhenAvailable")),
				RunOnlyIfNetworkAvailable = TryParseBool(GetElementValue(settings, ns + "RunOnlyIfNetworkAvailable")),
				UseUnifiedSchedulingEngine = TryParseBool(GetElementValue(settings, ns + "UseUnifiedSchedulingEngine")),
				ExecutionTimeLimit = GetElementValue(settings, ns + "ExecutionTimeLimit"),
				MultipleInstancesPolicy = GetElementValue(settings, ns + "MultipleInstancesPolicy"),
				Priority = TryParseInt(GetElementValue(settings, ns + "Priority")),
				NetworkProfileName = GetElementValue(networkSettings, ns + "Name") ?? GetElementValue(networkSettings, ns + "Id"),
				IdleDuration = GetElementValue(idleSettings, ns + "Duration"),
				IdleWaitTimeout = GetElementValue(idleSettings, ns + "WaitTimeout"),
				StopOnIdleEnd = TryParseBool(GetElementValue(idleSettings, ns + "StopOnIdleEnd")),
				RestartOnIdle = TryParseBool(GetElementValue(idleSettings, ns + "RestartOnIdle")),
				MaintenancePeriod = GetElementValue(maintenance, ns + "Period"),
				MaintenanceDeadline = GetElementValue(maintenance, ns + "Deadline"),
				MaintenanceExclusive = TryParseBool(GetElementValue(maintenance, ns + "Exclusive"))
			};
		}

		private static IReadOnlyList<TboScheduledTaskTriggerInfo>? ParseTriggers(XElement root, XNamespace ns)
		{
			var triggersRoot = root.Element(ns + "Triggers");
			if (triggersRoot == null)
				return null;

			var triggers = new List<TboScheduledTaskTriggerInfo>();
			foreach (var trigger in triggersRoot.Elements())
			{
				var repetition = trigger.Element(ns + "Repetition");
				var info = new TboScheduledTaskTriggerInfo
				{
					TriggerType = trigger.Name.LocalName,
					Id = trigger.Attribute("id")?.Value,
					StartBoundary = GetElementValue(trigger, ns + "StartBoundary"),
					EndBoundary = GetElementValue(trigger, ns + "EndBoundary"),
					Enabled = TryParseBool(GetElementValue(trigger, ns + "Enabled")),
					Delay = GetElementValue(trigger, ns + "Delay"),
					UserId = GetElementValue(trigger, ns + "UserId"),
					ExecutionTimeLimit = GetElementValue(trigger, ns + "ExecutionTimeLimit"),
					RandomDelay = GetElementValue(trigger, ns + "RandomDelay"),
					RepetitionInterval = GetElementValue(repetition, ns + "Interval"),
					RepetitionDuration = GetElementValue(repetition, ns + "Duration"),
					RepetitionStopAtDurationEnd = TryParseBool(GetElementValue(repetition, ns + "StopAtDurationEnd")),
					Subscription = GetElementValue(trigger, ns + "Subscription"),
					StateChange = GetElementValue(trigger, ns + "StateChange")
				};

				var excluded = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
				{
					"StartBoundary",
					"EndBoundary",
					"Enabled",
					"Delay",
					"UserId",
					"ExecutionTimeLimit",
					"RandomDelay",
					"Interval",
					"Duration",
					"StopAtDurationEnd",
					"Subscription",
					"StateChange"
				};

				var extra = CollectLeafValues(trigger, excluded);
				if (extra.Count > 0)
					info = new TboScheduledTaskTriggerInfo
					{
						TriggerType = info.TriggerType,
						Id = info.Id,
						StartBoundary = info.StartBoundary,
						EndBoundary = info.EndBoundary,
						Enabled = info.Enabled,
						Delay = info.Delay,
						UserId = info.UserId,
						ExecutionTimeLimit = info.ExecutionTimeLimit,
						RandomDelay = info.RandomDelay,
						RepetitionInterval = info.RepetitionInterval,
						RepetitionDuration = info.RepetitionDuration,
						RepetitionStopAtDurationEnd = info.RepetitionStopAtDurationEnd,
						Subscription = info.Subscription,
						StateChange = info.StateChange,
						Properties = extra
					};

				triggers.Add(info);
			}

			return triggers;
		}

		private static IReadOnlyList<TboScheduledTaskActionInfo>? ParseActions(XElement root, XNamespace ns)
		{
			var actionsRoot = root.Element(ns + "Actions");
			if (actionsRoot == null)
				return null;

			var context = actionsRoot.Attribute("Context")?.Value;
			var actions = new List<TboScheduledTaskActionInfo>();
			foreach (var action in actionsRoot.Elements())
			{
				var type = action.Name.LocalName;
				var info = new TboScheduledTaskActionInfo
				{
					ActionType = type,
					Context = context,
					Command = GetElementValue(action, ns + "Command"),
					Arguments = GetElementValue(action, ns + "Arguments"),
					WorkingDirectory = GetElementValue(action, ns + "WorkingDirectory"),
					ClassId = GetElementValue(action, ns + "ClassId"),
					Data = GetElementValue(action, ns + "Data")
				};

				var excluded = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
				{
					"Command",
					"Arguments",
					"WorkingDirectory",
					"ClassId",
					"Data"
				};

				var extra = CollectLeafValues(action, excluded);
				if (extra.Count > 0)
					info = new TboScheduledTaskActionInfo
					{
						ActionType = info.ActionType,
						Context = info.Context,
						Command = info.Command,
						Arguments = info.Arguments,
						WorkingDirectory = info.WorkingDirectory,
						ClassId = info.ClassId,
						Data = info.Data,
						Properties = extra
					};

				actions.Add(info);
			}

			return actions;
		}

		private static Dictionary<string, string> CollectLeafValues(XElement element, HashSet<string> excluded)
		{
			var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
			foreach (var descendant in element.Descendants())
			{
				if (descendant.HasElements)
					continue;

				var name = descendant.Name.LocalName;
				if (excluded.Contains(name))
					continue;

				var value = descendant.Value;
				if (string.IsNullOrWhiteSpace(value))
					continue;

				if (!values.ContainsKey(name))
					values.Add(name, value);
			}

			return values;
		}

		private static string? GetElementValue(XElement? parent, XName name)
		{
			return parent?.Element(name)?.Value;
		}

		private static bool? TryParseBool(string? value)
		{
			if (string.IsNullOrWhiteSpace(value))
				return null;

			if (bool.TryParse(value, out var parsed))
				return parsed;

			if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var numeric))
				return numeric != 0;

			return null;
		}

		private static int? TryParseInt(string? value)
		{
			if (string.IsNullOrWhiteSpace(value))
				return null;

			if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
				return parsed;

			return null;
		}

		private static UncPath ResolveTaskFilePath(string serverName, string? taskFilePath, string taskPath)
		{
			if (!string.IsNullOrWhiteSpace(taskFilePath)
				&& UncPath.TryParse(taskFilePath, out var uncPath)
				&& uncPath != null)
				return uncPath;

			var relativePath = NormalizeRelativePath(taskPath);
			var root = UncPath.Parse($"\\\\{serverName}\\C$\\{TasksFolderPath}");
			return root.Append(relativePath);
		}

		private byte[]? TryReadTaskCacheSecurityDescriptorBytes(ISmbProviderInfo smb, string taskPath, CancellationToken cancellationToken)
		{
			try
			{
				return ExecuteRegistryOperation(smb, cancellationToken, session =>
				{
					var relative = NormalizeRelativePath(taskPath);
					var subkeyPath = string.IsNullOrWhiteSpace(relative)
						? TaskCacheTreePath
						: $"{TaskCacheTreePath}\\{relative}";

					var spec = new RegistryPathSpec(
						RegistryRootKey.LocalMachine,
						RemoteRegistryClient.GetRootName(RegistryRootKey.LocalMachine),
						subkeyPath);

					using var key = OpenRegistryKey(
						session.Client,
						spec,
						RegistryAccessRights.QueryValue,
						RegistryAccessRights.EnumerateSubkeys,
						cancellationToken);

					var valueInfo = key.GetValue("SD", cancellationToken).GetAwaiter().GetResult();
					return RegistryHelpers.ExtractValueBytes(valueInfo);
				});
			}
			catch (NtstatusException ex) when (ex.StatusCode == Ntstatus.STATUS_PIPE_BUSY)
			{
				this.LogWarning(smb, $"Get-TBOScheduledTaskDetails could not read TaskCache security descriptor for '{taskPath}' (STATUS_PIPE_BUSY).");
				return null;
			}
			catch (Win32Exception ex) when (IsMissingKey(ex) || ex.NativeErrorCode == (int)Win32ErrorCode.ERROR_ACCESS_DENIED)
			{
				return null;
			}
			catch (Exception ex)
			{
				this.LogException(smb, $"Get-TBOScheduledTaskDetails failed to read TaskCache security descriptor for '{taskPath}'", ex);
				return null;
			}
		}

	}
}
