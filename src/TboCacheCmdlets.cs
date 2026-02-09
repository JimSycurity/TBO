using System;
using System.Collections.Generic;
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
}

