using System;
using System.ComponentModel;
using System.Management.Automation;
using System.Text;
using System.Threading;
using Titanis.Msrpc.Msrrp;
using Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboRegAutoLogonInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string KeyPath { get; init; } = string.Empty;
		public string? DefaultUserName { get; init; }
		public string? DefaultDomainName { get; init; }
		public string? DefaultPassword { get; init; }
		public string? AltDefaultUserName { get; init; }
		public string? AltDefaultDomainName { get; init; }
		public string? AltDefaultPassword { get; init; }
		public string? DefaultLogonDomain { get; init; }
		public string? AutoAdminLogon { get; init; }
		public string? ForceAutoLogon { get; init; }
		public string? AutoLogonCount { get; init; }
	}

	[Cmdlet(VerbsCommon.Get, "TBORegAutoLogon")]
	[OutputType(typeof(TboRegAutoLogonInfo))]
	public sealed class GetTBORegAutoLogon : TboRegCmdlet
	{
		private const string WinlogonPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			ExecuteRegistryOperation(smb, cancellationToken, session =>
			{
				var winlogonSpec = new RegistryPathSpec(
					RegistryRootKey.LocalMachine,
					RemoteRegistryClient.GetRootName(RegistryRootKey.LocalMachine),
					WinlogonPath);

				using var winlogonKey = OpenRegistryKey(session.Client, winlogonSpec, RegistryAccessRights.QueryValue, cancellationToken);

				this.WriteObject(new TboRegAutoLogonInfo
				{
					ServerName = this.ServerName,
					KeyPath = winlogonSpec.KeyPath,
					DefaultUserName = TryReadValueString(winlogonKey, "DefaultUserName", cancellationToken),
					DefaultDomainName = TryReadValueString(winlogonKey, "DefaultDomainName", cancellationToken),
					DefaultPassword = TryReadValueString(winlogonKey, "DefaultPassword", cancellationToken),
					AltDefaultUserName = TryReadValueString(winlogonKey, "AltDefaultUserName", cancellationToken),
					AltDefaultDomainName = TryReadValueString(winlogonKey, "AltDefaultDomainName", cancellationToken),
					AltDefaultPassword = TryReadValueString(winlogonKey, "AltDefaultPassword", cancellationToken),
					DefaultLogonDomain = TryReadValueString(winlogonKey, "DefaultLogonDomain", cancellationToken),
					AutoAdminLogon = TryReadValueString(winlogonKey, "AutoAdminLogon", cancellationToken),
					ForceAutoLogon = TryReadValueString(winlogonKey, "ForceAutoLogon", cancellationToken),
					AutoLogonCount = TryReadValueString(winlogonKey, "AutoLogonCount", cancellationToken)
				});
			});
		}

		private static string? TryReadValueString(RegistryKey key, string name, CancellationToken cancellationToken)
		{
			try
			{
				var valueInfo = key.GetValue(name, cancellationToken).GetAwaiter().GetResult();
				if (valueInfo.TypedValue is string str && !string.IsNullOrEmpty(str))
					return str;

				if (valueInfo.Bytes != null && valueInfo.Bytes.Length > 0)
					return DecodeUnicodeString(valueInfo.Bytes);
			}
			catch (Win32Exception ex) when (IsMissingKey(ex))
			{
			}

			return null;
		}

		private static string? DecodeUnicodeString(byte[] bytes)
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

		private static bool IsMissingKey(Win32Exception ex)
		{
			return ex.NativeErrorCode is (int)Win32ErrorCode.ERROR_FILE_NOT_FOUND
				or (int)Win32ErrorCode.ERROR_PATH_NOT_FOUND
				or (int)Win32ErrorCode.ERROR_BAD_PATHNAME;
		}
	}
}
