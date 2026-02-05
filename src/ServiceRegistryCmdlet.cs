using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Threading;
using Titanis.Msrpc.Msrrp;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public abstract class ServiceRegistryCmdletBase : TboRegCmdlet
	{
		protected const string DefaultServicesPath = @"HKLM\SYSTEM\CurrentControlSet\Services";
		protected const string SecuritySubkeyName = "Security";
		protected const string SecurityValueName = "Security";

		protected static List<string> FilterNames(string[]? names)
		{
			if (names == null || names.Length == 0)
				return new List<string>();

			var filtered = new List<string>(names.Length);
			foreach (var name in names)
			{
				if (!string.IsNullOrWhiteSpace(name))
					filtered.Add(name.Trim());
			}

			return filtered;
		}

		protected static bool MatchesAnyPattern(IReadOnlyList<WildcardPattern> patterns, string value)
		{
			if (patterns.Count == 0)
				return false;

			foreach (var pattern in patterns)
			{
				if (pattern.IsMatch(value))
					return true;
			}

			return false;
		}

		protected List<RegistrySubkeyInfo> CollectServiceSubkeys(
			ISmbProviderInfo smb,
			IRegistryKey servicesKey,
			RegistryKeyInfo servicesInfo,
			RegistryPathSpec servicesPath,
			CancellationToken cancellationToken,
			string contextLabel)
		{
			List<RegistrySubkeyInfo> subkeys;
			try
			{
				subkeys = CollectSubkeys(servicesKey, cancellationToken);
			}
			catch (Exception ex)
			{
				this.LogException(smb, $"{contextLabel} failed to enumerate service keys", ex);
				throw;
			}

			if (servicesInfo.SubkeyCount > 0 && subkeys.Count != servicesInfo.SubkeyCount)
			{
				this.LogWarning(
					smb,
					$"{contextLabel} enumerated {subkeys.Count} of {servicesInfo.SubkeyCount} subkeys under {servicesPath.KeyPath}. Some services may be missing.");
			}

			return subkeys;
		}
	}
}
