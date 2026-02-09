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
		Dot = 2
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
				_ => RenderJson(graph)
			};

			this.WriteObject(output);
		}

		private static string RenderJson(TboCacheDatabase.GraphData graph)
		{
			using var ms = new MemoryStream();

			using (var writer = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = true }))
			{
				writer.WriteStartObject();
				writer.WriteString("schema", "tbo.cache.graph.v1");

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
					writer.WriteStartObject();
					writer.WriteString("id", $"principal:{p.PrincipalId}");
					writer.WriteString("type", "principal");
					writer.WriteNumber("principalId", p.PrincipalId);
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
							targetNodeId: $"principal:{o.PrincipalId.Value}");
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

			foreach (var m in graph.Machines)
			{
				var label = $"machine\\n{m.ServerName}";
				sb.AppendLine($"  m{m.MachineId} [shape=box, label=\"{DotEscape(label)}\"];");
			}

			foreach (var p in graph.Principals)
			{
				var display = GetPrincipalDisplay(p.PrincipalId, p.Sid, p.Domain, p.Name);
				var label = string.IsNullOrWhiteSpace(p.Type)
					? $"principal\\n{display}"
					: $"principal ({p.Type})\\n{display}";
				sb.AppendLine($"  p{p.PrincipalId} [shape=ellipse, label=\"{DotEscape(label)}\"];");
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
					sb.AppendLine($"  m{o.MachineId} -> p{o.PrincipalId.Value} [label=\"{DotEscape(label)}\"];");

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
	}
}
