using System;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public partial class SmbProviderInfo
	{
		internal void LogDiagnostic(string message)
		{
			if (string.IsNullOrWhiteSpace(message))
				return;

			try
			{
				this._log?.WriteDiagnostic(message);
			}
			catch
			{
			}

			try
			{
				System.Diagnostics.Trace.TraceInformation(message);
			}
			catch
			{
			}
		}

		internal void LogVerbose(string message)
		{
			if (string.IsNullOrWhiteSpace(message))
				return;

			try
			{
				this._log?.WriteVerbose(message);
			}
			catch
			{
			}

			try
			{
				System.Diagnostics.Trace.TraceInformation(message);
			}
			catch
			{
			}
		}

		internal void LogInfo(string message)
		{
			if (string.IsNullOrWhiteSpace(message))
				return;

			try
			{
				this._log?.WriteInfo(message);
			}
			catch
			{
			}

			try
			{
				System.Diagnostics.Trace.TraceInformation(message);
			}
			catch
			{
			}
		}

		internal void LogWarning(string message)
		{
			LogWarning(message, emitToConsole: true);
		}

		internal void LogWarning(string message, bool emitToConsole)
		{
			if (string.IsNullOrWhiteSpace(message))
				return;

			try
			{
				this._log?.WriteWarning(message);
			}
			catch
			{
			}

			if (!emitToConsole)
				return;

			try
			{
				System.Diagnostics.Trace.TraceWarning(message);
			}
			catch
			{
			}

			try
			{
				Console.Error.WriteLine($"WARNING: {message}");
			}
			catch
			{
			}
		}

		internal void LogException(string context, Exception ex)
		{
			if (string.IsNullOrWhiteSpace(context) || ex == null)
				return;

			try
			{
				this._log?.WriteError($"{context}: {ex.GetType().FullName}: {ex.Message}");
				this._log?.WriteDiagnostic(ex.ToString());
			}
			catch
			{
			}
		}
	}
}
