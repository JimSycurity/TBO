using System;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public partial class SmbProviderInfo
	{
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
