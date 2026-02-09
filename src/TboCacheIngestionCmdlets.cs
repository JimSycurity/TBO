using System;
using System.Management.Automation;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboCacheObservation
	{
		public string CachePath { get; init; } = "";

		public long ObservationId { get; init; }
		public DateTime ObservedUtc { get; init; }
		public int? Confidence { get; init; }
		public string? ContextJson { get; init; }

		public long MachineId { get; init; }
		public string ServerName { get; init; } = "";

		public long? PrincipalId { get; init; }
		public string? PrincipalSid { get; init; }
		public string? PrincipalDomain { get; init; }
		public string? PrincipalName { get; init; }
		public string? PrincipalType { get; init; }

		public long? CredentialId { get; init; }
		public string? CredentialKind { get; init; }
		public string? CredentialIdentifier { get; init; }

		public string SourceKind { get; init; } = "";
		public string? SourcePath { get; init; }
	}

	[Cmdlet(VerbsCommon.Add, "TBOCacheObservation", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.Medium)]
	[OutputType(typeof(TboCacheObservation))]
	public sealed class AddTBOCacheObservation : PSCmdlet
	{
		[Parameter(Mandatory = true)]
		[ValidateNotNullOrEmpty]
		public string ServerName { get; set; } = "";

		[Parameter]
		[ValidateNotNullOrEmpty]
		public string SourceKind { get; set; } = "Manual";

		[Parameter]
		public string? SourcePath { get; set; }

		[Parameter]
		public DateTime? ObservedUtc { get; set; }

		[Parameter]
		[ValidateRange(0, 100)]
		public int? Confidence { get; set; }

		[Parameter]
		public string? ContextJson { get; set; }

		[Parameter]
		public string? PrincipalSid { get; set; }

		[Parameter]
		public string? PrincipalDomain { get; set; }

		[Parameter]
		public string? PrincipalName { get; set; }

		[Parameter]
		public string? PrincipalType { get; set; }

		[Parameter]
		public string? CredentialKind { get; set; }

		[Parameter]
		public string? CredentialIdentifier { get; set; }

		[Parameter]
		public string? Path { get; set; }

		protected override void ProcessRecord()
		{
			var resolvedPath = TboCacheDatabase.ResolveCachePath(this.Path);

			if (!this.ShouldProcess(resolvedPath, $"Add cache observation for {this.ServerName}"))
				return;

			var args = new TboCacheIngestion.AddObservationArgs
			{
				ServerName = this.ServerName,
				SourceKind = this.SourceKind,
				SourcePath = this.SourcePath,
				ObservedUtc = this.ObservedUtc,
				Confidence = this.Confidence,
				ContextJson = this.ContextJson,

				PrincipalSid = this.PrincipalSid,
				PrincipalDomain = this.PrincipalDomain,
				PrincipalName = this.PrincipalName,
				PrincipalType = this.PrincipalType,

				CredentialKind = this.CredentialKind,
				CredentialIdentifier = this.CredentialIdentifier,

				CachePath = this.Path
			};

			TboCacheIngestion.AddObservationResult result;
			try
			{
				result = TboCacheIngestion.AddObservation(args, msg => this.WriteVerbose(msg));
			}
			catch (Exception ex)
			{
				throw new RuntimeException("Failed to add cache observation.", ex);
			}

			this.WriteObject(new TboCacheObservation
			{
				CachePath = result.CachePath,

				ObservationId = result.ObservationId,
				ObservedUtc = result.ObservedUtc,
				Confidence = result.Confidence,
				ContextJson = result.ContextJson,

				MachineId = result.MachineId,
				ServerName = result.ServerName,

				PrincipalId = result.PrincipalId,
				PrincipalSid = result.PrincipalSid,
				PrincipalDomain = result.PrincipalDomain,
				PrincipalName = result.PrincipalName,
				PrincipalType = result.PrincipalType,

				CredentialId = result.CredentialId,
				CredentialKind = result.CredentialKind,
				CredentialIdentifier = result.CredentialIdentifier,

				SourceKind = result.SourceKind,
				SourcePath = result.SourcePath,
			});
		}
	}
}
