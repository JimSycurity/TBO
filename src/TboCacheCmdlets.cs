using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Management.Automation;

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
}
