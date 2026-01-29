using System;
using System.Globalization;
using System.IO;
using System.Management.Automation;
using System.Text;
using Titanis;
using Titanis.Smb2;
using Winterop = Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	[Cmdlet(VerbsData.Out, "TBOSmbFile", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.Medium)]
	public sealed class OutTBOSmbFile : SmbCmdlet
	{
		private const string PathParameterSet = "Path";
		private const string LiteralPathParameterSet = "LiteralPath";

		[Parameter(Mandatory = true, Position = 0, ParameterSetName = PathParameterSet)]
		public string Path { get; set; } = string.Empty;

		[Parameter(Mandatory = true, ParameterSetName = LiteralPathParameterSet)]
		[Alias("PSPath")]
		public string LiteralPath { get; set; } = string.Empty;

		[Parameter(ValueFromPipeline = true)]
		public object? InputObject { get; set; }

		[Parameter]
		public SwitchParameter Append { get; set; }

		[Parameter]
		public SwitchParameter NoClobber { get; set; }

		[Parameter]
		public SwitchParameter Force { get; set; }

		[Parameter]
		public SwitchParameter NoNewline { get; set; }

		[Parameter]
		public Encoding? Encoding { get; set; }

		private Smb2OpenFile? _file;
		private Smb2FileStream? _stream;
		private StreamWriter? _writer;
		private bool _initialized;
		private bool _shouldWrite = true;

		protected override void ProcessRecord(ISmbProviderInfo smb)
		{
			if (!this._initialized)
			{
				this._initialized = true;
				InitializeWriter(smb);
			}

			if (!this._shouldWrite)
				return;

			try
			{
				if (!this.MyInvocation.ExpectingInput && this.InputObject == null)
					return;

				WriteValue(this.InputObject);
			}
			catch
			{
				DisposeWriter();
				throw;
			}
		}

		protected override void EndProcessing()
		{
			DisposeWriter();
			base.EndProcessing();
		}

		protected override void StopProcessing()
		{
			DisposeWriter();
			base.StopProcessing();
		}

		private void InitializeWriter(ISmbProviderInfo smb)
		{
			if (this.Append.IsPresent && this.NoClobber.IsPresent)
				throw new ArgumentException("NoClobber cannot be used with Append.", nameof(NoClobber));

			var targetPath = GetTargetPath();
			var uncPath = ResolveToUncPath(targetPath, this.ParameterSetName);
			if (string.IsNullOrEmpty(uncPath.ShareName))
				throw new ArgumentException($"The UNC path must include a share name: {uncPath}", this.ParameterSetName);

			var snapshotPath = ResolveSnapshotPath(uncPath);
			if (snapshotPath.TimeWarpToken.HasValue)
				throw new NotSupportedException("Snapshot paths are read-only.");
			if (string.IsNullOrEmpty(snapshotPath.ResolvedPath.ShareRelativePath))
				throw new ArgumentException("Path must include a file name.", this.ParameterSetName);

			if (!this.ShouldProcess(snapshotPath.ResolvedPath.ToString(), "Write SMB file"))
			{
				this._shouldWrite = false;
				return;
			}

			var noClobber = this.NoClobber.IsPresent && !this.Force.IsPresent;
			var createDisposition = this.Append.IsPresent
				? Smb2CreateDisposition.OpenIf
				: noClobber
					? Smb2CreateDisposition.Create
					: Smb2CreateDisposition.OverwriteIf;
			var desiredAccess = (uint)(
				Smb2FileAccessRights.ReadData
				| Smb2FileAccessRights.WriteData
				| Smb2FileAccessRights.AppendData
				| Smb2FileAccessRights.ReadAttributes
				| Smb2FileAccessRights.WriteAttributes
				| Smb2FileAccessRights.ReadEa
				| Smb2FileAccessRights.WriteEa
				| Smb2FileAccessRights.ReadControl
				| Smb2FileAccessRights.Synchronize);

			var createInfo = new Smb2CreateInfo
			{
				CreateDisposition = createDisposition,
				DesiredAccess = desiredAccess,
				ShareAccess = Smb2ShareAccess.ReadWriteDelete,
				ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
				CreateOptions = Smb2FileCreateOptions.NonDirectory
					| Smb2FileCreateOptions.SynchronousIoNonalert
					| Smb2FileCreateOptions.OpenForBackupIntent,
				FileAttributes = Winterop.FileAttributes.Normal,
				TimeWarpToken = snapshotPath.TimeWarpToken
			};

			Smb2OpenFile? file = null;
			try
			{
				file = (Smb2OpenFile)smb.SmbClient.CreateFileAsync(snapshotPath.ResolvedPath, createInfo, FileAccess.ReadWrite, System.Threading.CancellationToken.None)
					.GetAwaiter().GetResult();

				if (file.IsDirectory)
					throw new IOException($"Path '{snapshotPath.ResolvedPath}' is a directory.");

				this._file = file;
				file = null;
			}
			finally
			{
				if (file != null)
					file.CloseAsync(System.Threading.CancellationToken.None).GetAwaiter().GetResult();
			}

			this._stream = this._file.GetStream(false);
			if (this.Append.IsPresent)
				this._stream.Seek(0, SeekOrigin.End);

			var encoding = this.Encoding ?? Encoding.UTF8;
			this._writer = new StreamWriter(this._stream, encoding, 4096, false);
		}

		private void WriteValue(object? value)
		{
			if (this._writer == null)
				throw new InvalidOperationException("Writer is not initialized.");

			var text = Convert.ToString(value, CultureInfo.CurrentCulture) ?? string.Empty;
			if (this.NoNewline.IsPresent)
				this._writer.Write(text);
			else
				this._writer.WriteLine(text);

			this._writer.Flush();
		}

		private void DisposeWriter()
		{
			var writer = this._writer;
			var stream = this._stream;
			var file = this._file;

			this._writer = null;
			this._stream = null;
			this._file = null;

			if (writer != null)
				writer.Dispose();

			if (stream != null)
				stream.Dispose();

			if (file != null)
				file.CloseAsync(System.Threading.CancellationToken.None).GetAwaiter().GetResult();
		}

		private string GetTargetPath()
		{
			return this.ParameterSetName == LiteralPathParameterSet
				? this.LiteralPath
				: this.Path;
		}

		private static SnapshotPath ResolveSnapshotPath(UncPath uncPath)
		{
			if (TrySplitTimeWarpToken(uncPath, out var resolvedPath, out var timeWarpToken))
				return new SnapshotPath(resolvedPath, timeWarpToken);

			return new SnapshotPath(uncPath, null);
		}

		private static bool TrySplitTimeWarpToken(UncPath uncPath, out UncPath resolvedPath, out DateTime? timeWarpToken)
		{
			resolvedPath = uncPath;
			timeWarpToken = null;

			var relativePath = uncPath.ShareRelativePath;
			if (string.IsNullOrEmpty(relativePath))
				return false;

			var separatorIndex = relativePath.IndexOf('\\');
			var firstSegment = separatorIndex >= 0 ? relativePath.Substring(0, separatorIndex) : relativePath;
			if (!firstSegment.StartsWith("@GMT-", StringComparison.OrdinalIgnoreCase))
				return false;

			try
			{
				var snapshot = FileSnapshotInfo.Parse(firstSegment.ToUpperInvariant());
				timeWarpToken = snapshot.Timestamp;
			}
			catch
			{
				return false;
			}

			var remainder = separatorIndex >= 0 ? relativePath.Substring(separatorIndex + 1) : null;
			resolvedPath = string.IsNullOrEmpty(remainder)
				? new UncPath(uncPath.ServerName, uncPath.Port, uncPath.ShareName, string.Empty)
				: new UncPath(uncPath.ServerName, uncPath.Port, uncPath.ShareName, remainder);
			return true;
		}

		private UncPath ResolveToUncPath(string path, string paramName)
		{
			if (string.IsNullOrWhiteSpace(path))
				throw new ArgumentException("Path must be provided.", paramName);

			if (UncPath.TryParse(path, out var uncPath) && uncPath != null)
				return uncPath;

			ProviderInfo? providerInfo;
			PSDriveInfo? driveInfo;
			string providerPath;
			try
			{
				providerPath = this.SessionState.Path.GetUnresolvedProviderPathFromPSPath(path, out providerInfo, out driveInfo);
			}
			catch (Exception ex)
			{
				throw new ArgumentException($"Path could not be resolved: {path}", paramName, ex);
			}

			if (providerInfo == null || !providerInfo.Name.Equals(SmbProvider.ProviderName, StringComparison.OrdinalIgnoreCase))
				throw new ArgumentException($"Path must be a UNC path or a {SmbProvider.ProviderName} PSDrive path: {path}", paramName);

			if (UncPath.TryParse(providerPath, out var resolvedUnc) && resolvedUnc != null)
				return resolvedUnc;

			throw new ArgumentException($"Resolved provider path is not a UNC path: {providerPath}", paramName);
		}

		private readonly struct SnapshotPath
		{
			public SnapshotPath(UncPath resolvedPath, DateTime? timeWarpToken)
			{
				ResolvedPath = resolvedPath;
				TimeWarpToken = timeWarpToken;
			}

			public UncPath ResolvedPath { get; }
			public DateTime? TimeWarpToken { get; }
		}
	}
}
