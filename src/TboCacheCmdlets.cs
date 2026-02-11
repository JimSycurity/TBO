using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Text;
using System.Text.Json;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboCacheInfo
	{
		public string? Path { get; init; }
		public int SchemaVersion { get; init; }

		public long MachineCount { get; init; }
		public long PrincipalCount { get; init; }
		public long CredentialCount { get; init; }
		public long ObservationCount { get; init; }

		public long DpapiMasterKeyCount { get; init; }
		public long DpapiBlobCount { get; init; }

		public long WriteActivityCount { get; init; }
	}

	public sealed class TboCacheCredentialReuse
	{
		public long CredentialId { get; init; }
		public string CredentialKind { get; init; } = "";
		public string CredentialIdentifier { get; init; } = "";
		public long MachineCount { get; init; }

		public string ServerName { get; init; } = "";
		public string? PrincipalSid { get; init; }
		public string? PrincipalDomain { get; init; }
		public string? PrincipalName { get; init; }
		public string? PrincipalType { get; init; }

		public long ObservationCount { get; init; }
		public DateTime FirstObservedUtc { get; init; }
		public DateTime LastObservedUtc { get; init; }
	}

	public enum TboCacheEntryType
	{
		Machine = 1,
		Principal = 2,
		Credential = 3,
		Observation = 4
	}

	public enum TboCacheGraphFormat
	{
		Json = 1,
		Dot = 2,
		OpenGraph = 3
	}

	[Cmdlet(VerbsCommon.Get, "TBOCacheInfo")]
	[OutputType(typeof(TboCacheInfo))]
	public sealed class GetTBOCacheInfo : PSCmdlet
	{
		[Parameter]
		public string? Path { get; set; }

		protected override void ProcessRecord()
		{
			var resolvedPath = TboCacheDatabase.ResolveCachePath(this.Path);
			using var db = TboCacheDatabase.Open(this.Path, msg => this.WriteVerbose(msg));

			var (schemaVersion, _) = db.GetInfo(this.Path);
			var counts = db.GetCountsByTable();

			long GetCount(string table)
				=> counts.TryGetValue(table, out var count) ? count : 0;

			this.WriteObject(new TboCacheInfo
			{
				Path = resolvedPath,
				SchemaVersion = schemaVersion,
				MachineCount = GetCount("machines"),
				PrincipalCount = GetCount("principals"),
				CredentialCount = GetCount("credentials"),
				ObservationCount = GetCount("observations"),
				DpapiMasterKeyCount = GetCount("dpapi_masterkeys"),
				DpapiBlobCount = GetCount("dpapi_blobs"),
				WriteActivityCount = GetCount("write_activities"),
			});
		}
	}

	[Cmdlet(VerbsCommon.Clear, "TBOCache", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.High)]
	public sealed class ClearTBOCache : PSCmdlet
	{
		[Parameter]
		public string? Path { get; set; }

		protected override void ProcessRecord()
		{
			var resolvedPath = TboCacheDatabase.ResolveCachePath(this.Path);

			if (!this.ShouldProcess(resolvedPath, "Clear cache database (delete all rows)"))
				return;

			using var db = TboCacheDatabase.Open(this.Path, msg => this.WriteVerbose(msg));
			db.ClearAll();
		}
	}

	[Cmdlet(VerbsCommon.Remove, "TBOCacheEntry", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.High)]
	public sealed class RemoveTBOCacheEntry : PSCmdlet
	{
		private readonly List<long> _ids = new();

		[Parameter(Mandatory = true)]
		public TboCacheEntryType Type { get; set; }

		[Parameter(Mandatory = true, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
		public long[] Id { get; set; } = Array.Empty<long>();

		[Parameter]
		public string? Path { get; set; }

		protected override void ProcessRecord()
		{
			foreach (var id in this.Id ?? Array.Empty<long>())
			{
				if (id <= 0)
				{
					this.WriteError(new ErrorRecord(
						new ArgumentOutOfRangeException(nameof(this.Id), id, "Id must be a positive integer."),
						"TBOCacheEntryInvalidId",
						ErrorCategory.InvalidArgument,
						id));
					continue;
				}

				_ids.Add(id);
			}
		}

		protected override void EndProcessing()
		{
			if (_ids.Count == 0)
				return;

			var resolvedPath = TboCacheDatabase.ResolveCachePath(this.Path);
			var unique = _ids.Distinct().OrderBy(x => x).ToArray();

			if (!this.ShouldProcess(resolvedPath, $"Remove {this.Type} entries: {string.Join(", ", unique)}"))
				return;

			using var db = TboCacheDatabase.Open(this.Path, msg => this.WriteVerbose(msg));
			db.RemoveEntries(this.Type, unique);
		}
	}

	[Cmdlet(VerbsCommon.Get, "TBOCacheCredentialReuse")]
	[OutputType(typeof(TboCacheCredentialReuse))]
	public sealed class GetTBOCacheCredentialReuse : PSCmdlet
	{
		[Parameter]
		public string? Kind { get; set; }

		[Parameter]
		public string? Identifier { get; set; }

		[Parameter]
		[ValidateRange(2, int.MaxValue)]
		public int MinimumMachineCount { get; set; } = 2;

		[Parameter]
		public string? Path { get; set; }

		protected override void ProcessRecord()
		{
			using var db = TboCacheDatabase.Open(this.Path, msg => this.WriteVerbose(msg));
			var rows = db.QueryCredentialReuse(this.Kind, this.Identifier, this.MinimumMachineCount);

			foreach (var row in rows)
			{
				this.WriteObject(new TboCacheCredentialReuse
				{
					CredentialId = row.CredentialId,
					CredentialKind = row.Kind,
					CredentialIdentifier = row.Identifier,
					MachineCount = row.MachineCount,

					ServerName = row.ServerName,
					PrincipalSid = row.PrincipalSid,
					PrincipalDomain = row.PrincipalDomain,
					PrincipalName = row.PrincipalName,
					PrincipalType = row.PrincipalType,

					ObservationCount = row.ObservationCount,
					FirstObservedUtc = ParseDateTime(row.FirstObservedUtc),
					LastObservedUtc = ParseDateTime(row.LastObservedUtc),
				});
			}
		}

		private static DateTime ParseDateTime(string value)
		{
			if (string.IsNullOrWhiteSpace(value))
				return default;

			if (DateTime.TryParseExact(
				value,
				"O",
				CultureInfo.InvariantCulture,
				DateTimeStyles.RoundtripKind,
				out var parsed))
			{
				return parsed;
			}

			return DateTime.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
		}
	}

	[Cmdlet(VerbsData.Export, "TBOCacheGraph")]
	[OutputType(typeof(string))]
	public sealed class ExportTBOCacheGraph : PSCmdlet
	{
		[Parameter]
		public TboCacheGraphFormat Format { get; set; } = TboCacheGraphFormat.Json;

		[Parameter]
		public string? Path { get; set; }

		protected override void ProcessRecord()
		{
			using var db = TboCacheDatabase.Open(this.Path, msg => this.WriteVerbose(msg));
			var graph = db.QueryGraphData();

			var output = this.Format switch
			{
				TboCacheGraphFormat.Dot => RenderDot(graph),
				TboCacheGraphFormat.OpenGraph => RenderOpenGraph(graph),
				_ => RenderJson(graph)
			};

			this.WriteObject(output);
		}

		// BloodHound OpenGraph JSON export.
		//
		// Schema reference: https://bloodhound.specterops.io/opengraph/schema
		//
		// Important constraints:
		// - Node.id is a string and must be unique.
		// - Node.kinds is a string array (1..3 items). The first element is treated as the "primary" kind.
		// - Node/Edge properties is a flat key-value map where values must not be objects
		//   (strings, numbers, booleans, or arrays of primitives only).
		private static string RenderOpenGraph(TboCacheDatabase.GraphData graph)
		{
			using var ms = new MemoryStream();

			var principalNodeIds = BuildPrincipalNodeIds(graph);

			using (var writer = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = true }))
			{
				writer.WriteStartObject();

				writer.WriteStartObject("graph");

				writer.WriteStartArray("nodes");

				foreach (var m in graph.Machines)
					WriteOpenGraphMachineNode(writer, m);

				foreach (var p in graph.Principals)
					WriteOpenGraphPrincipalNode(writer, p, principalNodeIds);

				foreach (var c in graph.Credentials)
					WriteOpenGraphCredentialNode(writer, c);

				writer.WriteEndArray();

				writer.WriteStartArray("edges");

				foreach (var o in graph.Observations)
				{
					if (o.PrincipalId.HasValue)
					{
						WriteOpenGraphObservationEdge(
							writer,
							o,
							edgeKind: "ObservedPrincipal",
							targetNodeId: ResolvePrincipalNodeId(principalNodeIds, o.PrincipalId.Value),
							targetKind: "TBO.Principal");
					}

					if (o.CredentialId.HasValue)
					{
						WriteOpenGraphObservationEdge(
							writer,
							o,
							edgeKind: "ObservedCredential",
							targetNodeId: $"credential:{o.CredentialId.Value}",
							targetKind: "TBO.Credential");
					}
				}

				writer.WriteEndArray();

				writer.WriteEndObject(); // graph
				writer.WriteEndObject(); // root
			}

			return Encoding.UTF8.GetString(ms.ToArray());
		}

		private static void WriteOpenGraphMachineNode(Utf8JsonWriter writer, TboCacheDatabase.GraphMachineRow m)
		{
			writer.WriteStartObject();
			writer.WriteString("id", $"machine:{m.MachineId}");

			// Keep the primary kind generic for UI readability, while preserving a TBO-specific kind for filtering.
			writer.WriteStartArray("kinds");
			writer.WriteStringValue("Computer");
			writer.WriteStringValue("TBO.Machine");
			writer.WriteEndArray();

			writer.WriteStartObject("properties");
			writer.WriteString("objectid", $"machine:{m.MachineId}");
			writer.WriteNumber("machineId", m.MachineId);
			writer.WriteString("serverName", m.ServerName);
			writer.WriteString("name", m.ServerName);
			writer.WriteString("displayname", m.ServerName);
			writer.WriteString("firstSeenUtc", m.FirstSeenUtc);
			writer.WriteString("lastSeenUtc", m.LastSeenUtc);
			writer.WriteEndObject();

			writer.WriteEndObject();
		}

		private static void WriteOpenGraphPrincipalNode(
			Utf8JsonWriter writer,
			TboCacheDatabase.GraphPrincipalRow p,
			IReadOnlyDictionary<long, string> principalNodeIds)
		{
			var nodeId = ResolvePrincipalNodeId(principalNodeIds, p.PrincipalId);

			writer.WriteStartObject();
			writer.WriteString("id", nodeId);

			var primaryKind = MapPrincipalKind(p.Type);

			writer.WriteStartArray("kinds");
			writer.WriteStringValue(primaryKind);
			if (!string.Equals(primaryKind, "TBO.Principal", StringComparison.Ordinal))
				writer.WriteStringValue("TBO.Principal");
			writer.WriteEndArray();

			var display = BuildPrincipalDisplay(p.PrincipalId, p.Sid, p.Domain, p.Name);

			writer.WriteStartObject("properties");
			writer.WriteString("objectid", nodeId);
			writer.WriteNumber("principalId", p.PrincipalId);
			writer.WriteString("name", display);
			writer.WriteString("displayname", display);
			if (!string.IsNullOrWhiteSpace(p.Sid))
				writer.WriteString("sid", p.Sid);
			if (!string.IsNullOrWhiteSpace(p.Domain))
				writer.WriteString("domain", p.Domain);
			if (!string.IsNullOrWhiteSpace(p.Name))
				writer.WriteString("accountName", p.Name);
			if (!string.IsNullOrWhiteSpace(p.Type))
				writer.WriteString("principalType", p.Type);
			writer.WriteString("firstSeenUtc", p.FirstSeenUtc);
			writer.WriteString("lastSeenUtc", p.LastSeenUtc);
			writer.WriteEndObject();

			writer.WriteEndObject();
		}

		private static void WriteOpenGraphCredentialNode(Utf8JsonWriter writer, TboCacheDatabase.GraphCredentialRow c)
		{
			writer.WriteStartObject();
			writer.WriteString("id", $"credential:{c.CredentialId}");

			writer.WriteStartArray("kinds");
			writer.WriteStringValue("TBO.Credential");
			writer.WriteEndArray();

			var display = $"{c.Kind}:{c.Identifier}";

			writer.WriteStartObject("properties");
			writer.WriteString("objectid", $"credential:{c.CredentialId}");
			writer.WriteNumber("credentialId", c.CredentialId);
			writer.WriteString("kind", c.Kind);
			writer.WriteString("identifier", c.Identifier);
			writer.WriteString("name", display);
			writer.WriteString("displayname", display);
			writer.WriteString("firstSeenUtc", c.FirstSeenUtc);
			writer.WriteString("lastSeenUtc", c.LastSeenUtc);
			writer.WriteEndObject();

			writer.WriteEndObject();
		}

		private static void WriteOpenGraphObservationEdge(
			Utf8JsonWriter writer,
			TboCacheDatabase.GraphObservationRow o,
			string edgeKind,
			string targetNodeId,
			string targetKind)
		{
			writer.WriteStartObject();
			writer.WriteString("kind", edgeKind);

			writer.WriteStartObject("start");
			writer.WriteString("match_by", "id");
			writer.WriteString("value", $"machine:{o.MachineId}");
			writer.WriteString("kind", "TBO.Machine");
			writer.WriteEndObject();

			writer.WriteStartObject("end");
			writer.WriteString("match_by", "id");
			writer.WriteString("value", targetNodeId);
			writer.WriteString("kind", targetKind);
			writer.WriteEndObject();

			// Keep properties flat (no nested objects), per OpenGraph schema requirements.
			writer.WriteStartObject("properties");
			writer.WriteNumber("observationId", o.ObservationId);
			writer.WriteString("observedUtc", o.ObservedUtc);
			writer.WriteString("sourceKind", o.SourceKind);
			if (!string.IsNullOrWhiteSpace(o.SourcePath))
				writer.WriteString("sourcePath", o.SourcePath);
			if (o.Confidence.HasValue)
				writer.WriteNumber("confidence", o.Confidence.Value);
			if (!string.IsNullOrWhiteSpace(o.ContextJson))
				writer.WriteString("contextJson", o.ContextJson);
			writer.WriteEndObject();

			writer.WriteEndObject();
		}

		private static string MapPrincipalKind(string? principalType)
		{
			if (string.IsNullOrWhiteSpace(principalType))
				return "TBO.Principal";

			// These are just for better UI icons/labels in BloodHound; they are not semantics for TBO.
			return principalType.Trim() switch
			{
				"User" => "User",
				"Group" => "Group",
				"Computer" => "Computer",
				_ => "TBO.Principal"
			};
		}

		private static string BuildPrincipalDisplay(long principalId, string? sid, string? domain, string? name)
		{
			var dn = string.IsNullOrWhiteSpace(domain) || string.IsNullOrWhiteSpace(name)
				? null
				: $"{domain}\\{name}";

			if (!string.IsNullOrWhiteSpace(dn))
				return dn;

			if (!string.IsNullOrWhiteSpace(sid))
				return sid;

			return $"principal:{principalId}";
		}

		private static string RenderJson(TboCacheDatabase.GraphData graph)
		{
			using var ms = new MemoryStream();

			var principalNodeIds = BuildPrincipalNodeIds(graph);

			using (var writer = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = true }))
			{
				writer.WriteStartObject();
				writer.WriteString("schema", "tbo.cache.graph.v2");

				writer.WriteStartArray("nodes");
				foreach (var m in graph.Machines)
				{
					writer.WriteStartObject();
					writer.WriteString("id", $"machine:{m.MachineId}");
					writer.WriteString("type", "machine");
					writer.WriteNumber("machineId", m.MachineId);
					writer.WriteString("serverName", m.ServerName);
					writer.WriteString("firstSeenUtc", m.FirstSeenUtc);
					writer.WriteString("lastSeenUtc", m.LastSeenUtc);
					writer.WriteEndObject();
				}

				foreach (var p in graph.Principals)
				{
					var nodeId = ResolvePrincipalNodeId(principalNodeIds, p.PrincipalId);
					writer.WriteStartObject();
					writer.WriteString("id", nodeId);
					writer.WriteString("type", "principal");
					writer.WriteNumber("principalId", p.PrincipalId);
					writer.WriteString("scope", p.Scope);
					if (p.ScopeMachineId.HasValue)
						writer.WriteNumber("scopeMachineId", p.ScopeMachineId.Value);
					if (!string.IsNullOrWhiteSpace(p.Sid))
						writer.WriteString("sid", p.Sid);
					if (!string.IsNullOrWhiteSpace(p.Domain))
						writer.WriteString("domain", p.Domain);
					if (!string.IsNullOrWhiteSpace(p.Name))
						writer.WriteString("name", p.Name);
					if (!string.IsNullOrWhiteSpace(p.Type))
						writer.WriteString("principalType", p.Type);
					writer.WriteString("firstSeenUtc", p.FirstSeenUtc);
					writer.WriteString("lastSeenUtc", p.LastSeenUtc);
					writer.WriteEndObject();
				}

				foreach (var c in graph.Credentials)
				{
					writer.WriteStartObject();
					writer.WriteString("id", $"credential:{c.CredentialId}");
					writer.WriteString("type", "credential");
					writer.WriteNumber("credentialId", c.CredentialId);
					writer.WriteString("kind", c.Kind);
					writer.WriteString("identifier", c.Identifier);
					writer.WriteString("firstSeenUtc", c.FirstSeenUtc);
					writer.WriteString("lastSeenUtc", c.LastSeenUtc);
					writer.WriteEndObject();
				}
				writer.WriteEndArray();

				writer.WriteStartArray("edges");
				foreach (var o in graph.Observations)
				{
					if (o.PrincipalId.HasValue)
					{
						WriteObservationEdge(
							writer,
							o,
							edgeKind: "observed_principal",
							edgeIdSuffix: "principal",
							targetNodeId: ResolvePrincipalNodeId(principalNodeIds, o.PrincipalId.Value));
					}

					if (o.CredentialId.HasValue)
					{
						WriteObservationEdge(
							writer,
							o,
							edgeKind: "observed_credential",
							edgeIdSuffix: "credential",
							targetNodeId: $"credential:{o.CredentialId.Value}");
					}
				}
				writer.WriteEndArray();

				writer.WriteEndObject();
			}

			return Encoding.UTF8.GetString(ms.ToArray());
		}

		private static void WriteObservationEdge(
			Utf8JsonWriter writer,
			TboCacheDatabase.GraphObservationRow o,
			string edgeKind,
			string edgeIdSuffix,
			string targetNodeId)
		{
			writer.WriteStartObject();
			writer.WriteString("id", $"observation:{o.ObservationId}:{edgeIdSuffix}");
			writer.WriteString("type", edgeKind);
			writer.WriteNumber("observationId", o.ObservationId);
			writer.WriteString("source", $"machine:{o.MachineId}");
			writer.WriteString("target", targetNodeId);
			writer.WriteString("observedUtc", o.ObservedUtc);
			writer.WriteString("sourceKind", o.SourceKind);
			if (!string.IsNullOrWhiteSpace(o.SourcePath))
				writer.WriteString("sourcePath", o.SourcePath);
			if (o.Confidence.HasValue)
				writer.WriteNumber("confidence", o.Confidence.Value);
			if (!string.IsNullOrWhiteSpace(o.ContextJson))
				writer.WriteString("contextJson", o.ContextJson);
			writer.WriteEndObject();
		}

		private static string RenderDot(TboCacheDatabase.GraphData graph)
		{
			var sb = new StringBuilder();
			sb.AppendLine("digraph tbo_cache {");
			sb.AppendLine("  rankdir=LR;");
			sb.AppendLine("  node [fontname=\"Consolas\", fontsize=10];");
			sb.AppendLine("  edge [fontname=\"Consolas\", fontsize=9];");
			sb.AppendLine();

			var dotPrincipalNodeIds = new Dictionary<long, string>();
			foreach (var p in graph.Principals)
				dotPrincipalNodeIds[p.PrincipalId] = GetDotPrincipalNodeId(p);

			foreach (var m in graph.Machines)
			{
				var label = $"machine\\n{m.ServerName}";
				sb.AppendLine($"  m{m.MachineId} [shape=box, label=\"{DotEscape(label)}\"];");
			}

			foreach (var p in graph.Principals)
			{
				var nodeId = dotPrincipalNodeIds[p.PrincipalId];
				var display = GetPrincipalDisplay(p.PrincipalId, p.Sid, p.Domain, p.Name);
				var label = string.IsNullOrWhiteSpace(p.Type)
					? $"principal\\n{display}"
					: $"principal ({p.Type})\\n{display}";
				sb.AppendLine($"  {nodeId} [shape=ellipse, label=\"{DotEscape(label)}\"];");
			}

			foreach (var c in graph.Credentials)
			{
				var label = $"credential ({c.Kind})\\n{c.Identifier}";
				sb.AppendLine($"  c{c.CredentialId} [shape=diamond, label=\"{DotEscape(label)}\"];");
			}

			sb.AppendLine();

			foreach (var o in graph.Observations)
			{
				var label = BuildObservationEdgeLabel(o);

				if (o.PrincipalId.HasValue)
				{
					var principalNodeId = dotPrincipalNodeIds.TryGetValue(o.PrincipalId.Value, out var nodeId)
						? nodeId
						: $"pg{o.PrincipalId.Value}";
					sb.AppendLine($"  m{o.MachineId} -> {principalNodeId} [label=\"{DotEscape(label)}\"];");
				}

				if (o.CredentialId.HasValue)
					sb.AppendLine($"  m{o.MachineId} -> c{o.CredentialId.Value} [label=\"{DotEscape(label)}\"];");
			}

			sb.AppendLine("}");
			return sb.ToString();
		}

		private static string BuildObservationEdgeLabel(TboCacheDatabase.GraphObservationRow o)
		{
			if (o.Confidence.HasValue)
				return $"obs {o.ObservationId}\\n{o.SourceKind}\\n{o.ObservedUtc}\\nconf={o.Confidence.Value}";

			return $"obs {o.ObservationId}\\n{o.SourceKind}\\n{o.ObservedUtc}";
		}

		private static string GetPrincipalDisplay(long principalId, string? sid, string? domain, string? name)
		{
			var dn = string.IsNullOrWhiteSpace(domain) || string.IsNullOrWhiteSpace(name)
				? null
				: $"{domain}\\{name}";

			if (!string.IsNullOrWhiteSpace(dn) && !string.IsNullOrWhiteSpace(sid))
				return $"{dn}\\n{sid}";

			if (!string.IsNullOrWhiteSpace(dn))
				return dn;

			if (!string.IsNullOrWhiteSpace(sid))
				return sid;

			return $"principal:{principalId}";
		}

		private static string DotEscape(string value)
		{
			if (value == null)
				return string.Empty;

			return value
				.Replace("\\", "\\\\", StringComparison.Ordinal)
				.Replace("\"", "\\\"", StringComparison.Ordinal)
				.Replace("\r", string.Empty, StringComparison.Ordinal)
				.Replace("\n", "\\n", StringComparison.Ordinal);
		}

		private static IReadOnlyDictionary<long, string> BuildPrincipalNodeIds(TboCacheDatabase.GraphData graph)
		{
			var ids = new Dictionary<long, string>();
			foreach (var p in graph.Principals)
				ids[p.PrincipalId] = GetPrincipalNodeId(p);

			return ids;
		}

		private static string ResolvePrincipalNodeId(IReadOnlyDictionary<long, string> principalNodeIds, long principalId)
		{
			if (principalNodeIds.TryGetValue(principalId, out var nodeId))
				return nodeId;

			// Fallback for inconsistent caches.
			return $"principal:unknown:{principalId}";
		}

		private static string GetPrincipalNodeId(TboCacheDatabase.GraphPrincipalRow p)
		{
			if (string.Equals(p.Scope, "Machine", StringComparison.OrdinalIgnoreCase))
			{
				var machinePart = p.ScopeMachineId.HasValue
					? p.ScopeMachineId.Value.ToString(CultureInfo.InvariantCulture)
					: "0";
				return $"principal:machine:{machinePart}:{p.PrincipalId}";
			}

			return $"principal:global:{p.PrincipalId}";
		}

		private static string GetDotPrincipalNodeId(TboCacheDatabase.GraphPrincipalRow p)
		{
			if (string.Equals(p.Scope, "Machine", StringComparison.OrdinalIgnoreCase))
			{
				var machinePart = p.ScopeMachineId.HasValue
					? p.ScopeMachineId.Value.ToString(CultureInfo.InvariantCulture)
					: "0";
				return $"pm{machinePart}_{p.PrincipalId}";
			}

			return $"pg{p.PrincipalId}";
		}

	}

	[Cmdlet(VerbsData.Export, "TBOCacheJson")]
	[OutputType(typeof(string))]
	public sealed class ExportTBOCacheJson : PSCmdlet
	{
		[Parameter]
		public string? Path { get; set; }

		protected override void ProcessRecord()
		{
			using var db = TboCacheDatabase.Open(this.Path, msg => this.WriteVerbose(msg));
			var (schemaVersion, resolvedPath) = db.GetInfo(this.Path);
			var graph = db.QueryGraphData();
			var dpapiMasterKeys = db.QueryDpapiMasterKeys();
			var dpapiBlobs = db.QueryDpapiBlobs();
			var writeActivities = db.QueryWriteActivities();

			using var ms = new MemoryStream();
			using (var writer = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = true }))
			{
				writer.WriteStartObject();

				writer.WriteString("schema", "tbo.cache.export.v1");
				writer.WriteString("exportedUtc", DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture));
				writer.WriteNumber("schemaVersion", schemaVersion);
				writer.WriteString("cachePath", resolvedPath);

				writer.WriteStartArray("machines");
				foreach (var m in graph.Machines)
				{
					writer.WriteStartObject();
					writer.WriteNumber("machineId", m.MachineId);
					writer.WriteString("serverName", m.ServerName);
					writer.WriteString("firstSeenUtc", m.FirstSeenUtc);
					writer.WriteString("lastSeenUtc", m.LastSeenUtc);
					writer.WriteEndObject();
				}
				writer.WriteEndArray();

				writer.WriteStartArray("principals");
				foreach (var p in graph.Principals)
				{
					writer.WriteStartObject();
					writer.WriteNumber("principalId", p.PrincipalId);
					writer.WriteString("scope", p.Scope);
					if (p.ScopeMachineId.HasValue)
						writer.WriteNumber("scopeMachineId", p.ScopeMachineId.Value);
					if (!string.IsNullOrWhiteSpace(p.Sid))
						writer.WriteString("sid", p.Sid);
					if (!string.IsNullOrWhiteSpace(p.Domain))
						writer.WriteString("domain", p.Domain);
					if (!string.IsNullOrWhiteSpace(p.Name))
						writer.WriteString("name", p.Name);
					if (!string.IsNullOrWhiteSpace(p.Type))
						writer.WriteString("principalType", p.Type);
					writer.WriteString("firstSeenUtc", p.FirstSeenUtc);
					writer.WriteString("lastSeenUtc", p.LastSeenUtc);
					writer.WriteEndObject();
				}
				writer.WriteEndArray();

				writer.WriteStartArray("credentials");
				foreach (var c in graph.Credentials)
				{
					writer.WriteStartObject();
					writer.WriteNumber("credentialId", c.CredentialId);
					writer.WriteString("kind", c.Kind);
					writer.WriteString("identifier", c.Identifier);
					writer.WriteString("firstSeenUtc", c.FirstSeenUtc);
					writer.WriteString("lastSeenUtc", c.LastSeenUtc);
					writer.WriteEndObject();
				}
				writer.WriteEndArray();

				writer.WriteStartArray("observations");
				foreach (var o in graph.Observations)
				{
					writer.WriteStartObject();
					writer.WriteNumber("observationId", o.ObservationId);
					writer.WriteNumber("machineId", o.MachineId);
					if (o.PrincipalId.HasValue)
						writer.WriteNumber("principalId", o.PrincipalId.Value);
					if (o.CredentialId.HasValue)
						writer.WriteNumber("credentialId", o.CredentialId.Value);
					writer.WriteString("sourceKind", o.SourceKind);
					if (!string.IsNullOrWhiteSpace(o.SourcePath))
						writer.WriteString("sourcePath", o.SourcePath);
					writer.WriteString("observedUtc", o.ObservedUtc);
					if (o.Confidence.HasValue)
						writer.WriteNumber("confidence", o.Confidence.Value);
					if (!string.IsNullOrWhiteSpace(o.ContextJson))
						writer.WriteString("contextJson", o.ContextJson);
					writer.WriteEndObject();
				}
				writer.WriteEndArray();

				writer.WriteStartArray("dpapiMasterKeys");
				foreach (var mk in dpapiMasterKeys)
				{
					writer.WriteStartObject();
					writer.WriteNumber("dpapiMasterKeyId", mk.DpapiMasterKeyId);
					writer.WriteNumber("machineId", mk.MachineId);
					writer.WriteString("scope", mk.Scope);
					if (!string.IsNullOrWhiteSpace(mk.UserSid))
						writer.WriteString("userSid", mk.UserSid);
					writer.WriteString("keyPath", mk.KeyPath);
					writer.WriteString("masterKeyGuid", mk.MasterKeyGuid);
					writer.WriteBoolean("isPreferred", mk.IsPreferred);
					if (mk.IsDomain.HasValue)
						writer.WriteBoolean("isDomain", mk.IsDomain.Value);
					if (mk.HashContext.HasValue)
						writer.WriteNumber("hashContext", mk.HashContext.Value);
					if (!string.IsNullOrWhiteSpace(mk.Hash))
						writer.WriteString("hash", mk.Hash);
					if (!string.IsNullOrWhiteSpace(mk.HashLine))
						writer.WriteString("hashLine", mk.HashLine);
					if (!string.IsNullOrWhiteSpace(mk.FailureReason))
						writer.WriteString("failureReason", mk.FailureReason);
					writer.WriteString("firstSeenUtc", mk.FirstSeenUtc);
					writer.WriteString("lastSeenUtc", mk.LastSeenUtc);
					writer.WriteEndObject();
				}
				writer.WriteEndArray();

				writer.WriteStartArray("dpapiBlobs");
				foreach (var b in dpapiBlobs)
				{
					writer.WriteStartObject();
					writer.WriteNumber("dpapiBlobId", b.DpapiBlobId);
					writer.WriteNumber("machineId", b.MachineId);
					writer.WriteString("blobKey", b.BlobKey);
					writer.WriteString("source", b.Source);
					writer.WriteString("path", b.Path);
					if (!string.IsNullOrWhiteSpace(b.ValueName))
						writer.WriteString("valueName", b.ValueName);
					if (b.ValueType.HasValue)
						writer.WriteNumber("valueType", b.ValueType.Value);
					if (b.DataLength.HasValue)
						writer.WriteNumber("dataLength", b.DataLength.Value);
					if (b.FileSize.HasValue)
						writer.WriteNumber("fileSize", b.FileSize.Value);
					writer.WriteNumber("matchOffset", b.MatchOffset);
					writer.WriteNumber("bytesScanned", b.BytesScanned);
					if (!string.IsNullOrWhiteSpace(b.CredentialGuid))
						writer.WriteString("credentialGuid", b.CredentialGuid);
					if (!string.IsNullOrWhiteSpace(b.MasterKeyGuid))
						writer.WriteString("masterKeyGuid", b.MasterKeyGuid);
					if (b.Flags.HasValue)
						writer.WriteNumber("flags", b.Flags.Value);
					if (!string.IsNullOrWhiteSpace(b.Description))
						writer.WriteString("description", b.Description);
					if (b.CryptAlgorithmId.HasValue)
						writer.WriteNumber("cryptAlgorithmId", b.CryptAlgorithmId.Value);
					if (b.HashAlgorithmId.HasValue)
						writer.WriteNumber("hashAlgorithmId", b.HashAlgorithmId.Value);
					if (!string.IsNullOrWhiteSpace(b.ParseFailureReason))
						writer.WriteString("parseFailureReason", b.ParseFailureReason);
					writer.WriteString("firstSeenUtc", b.FirstSeenUtc);
					writer.WriteString("lastSeenUtc", b.LastSeenUtc);
					writer.WriteEndObject();
				}
				writer.WriteEndArray();

				writer.WriteStartArray("writeActivities");
				foreach (var a in writeActivities)
				{
					writer.WriteStartObject();
					writer.WriteNumber("writeActivityId", a.WriteActivityId);
					writer.WriteNumber("machineId", a.MachineId);
					writer.WriteString("cmdlet", a.Cmdlet);
					writer.WriteString("kind", a.Kind);
					writer.WriteString("action", a.Action);
					writer.WriteString("target", a.Target);
					writer.WriteString("path", a.Path);
					if (!string.IsNullOrWhiteSpace(a.ValueName))
						writer.WriteString("valueName", a.ValueName);
					if (a.ValueType.HasValue)
						writer.WriteNumber("valueType", a.ValueType.Value);
					if (!string.IsNullOrWhiteSpace(a.BeforeBlobKind))
						writer.WriteString("beforeBlobKind", a.BeforeBlobKind);
					if (a.BeforeBlob != null)
						writer.WriteBase64String("beforeBlobBase64", a.BeforeBlob);
					if (!string.IsNullOrWhiteSpace(a.AfterBlobKind))
						writer.WriteString("afterBlobKind", a.AfterBlobKind);
					if (a.AfterBlob != null)
						writer.WriteBase64String("afterBlobBase64", a.AfterBlob);
					if (!string.IsNullOrWhiteSpace(a.ContextJson))
						writer.WriteString("contextJson", a.ContextJson);
					writer.WriteBoolean("success", a.Success);
					if (!string.IsNullOrWhiteSpace(a.FailureReason))
						writer.WriteString("failureReason", a.FailureReason);
					writer.WriteString("activityUtc", a.ActivityUtc);
					writer.WriteEndObject();
				}
				writer.WriteEndArray();

				writer.WriteEndObject();
			}

			this.WriteObject(Encoding.UTF8.GetString(ms.ToArray()));
		}
	}
}
