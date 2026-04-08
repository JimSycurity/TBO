using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Titanis.DceRpc;
using Titanis.DceRpc.Client;
using Titanis.Security;
using Titanis.Smb2;

namespace Titanis.Tbo.Smb2.PowerShell
{
	// [MS-BKRP] § 3.1.4 - BackupKey Remote Protocol
	//
	// The entire interface exposes a single operation, BackuprKey (opnum 0).
	// Behaviour is controlled by the pguidActionAgent parameter.
	//
	// Wire format references:
	//   - [MS-BKRP] for the protocol spec
	//   - Bad-Jubies/Exploits "MS-BKRP_padding_oracle_decrypt.py" for the bare-conformant-
	//     array marshalling of pDataIn (the [unique] referent ID shown in the IDL is NOT
	//     present on the wire — adding one causes RPC_X_BAD_STUB_DATA), and for the
	//     RetrieveBackupKey/RestoreKey action GUIDs.
	//     https://github.com/Bad-Jubies/Exploits/blob/main/MS-BKRP_padding_oracle_decrypt.py

	internal static class BkrpActionGuids
	{
		// [MS-BKRP] § 2.2.3 - Retrieve the DC's RSA backup-key certificate (DER/X.509)
		public static readonly Guid RetrieveBackupKey = new("018FF48A-EAB3-4A17-ABBA-9DEE04766FCE");

		// [MS-BKRP] § 2.2.3 - Restore / decrypt a domain backup blob
		public static readonly Guid RestoreKey = new("47270C64-2FC7-499B-AC5B-0E37CDCE899A");
	}

	public sealed class BkrpCallResult
	{
		public uint ReturnCode { get; init; }
		public byte[]? DataOut { get; init; }
		public uint DataOutLength { get; init; }
		internal byte[]? DiagStubBytes { get; init; }

		public bool IsSuccess => ReturnCode == 0;

		// 0x0d = ERROR_INVALID_DATA  - PKCS#1 padding was valid, inner SID check failed
		public bool IsPaddingValid => ReturnCode == 0 || ReturnCode == 0x0d;

		// 0x57 = ERROR_INVALID_PARAMETER - PKCS#1 padding was invalid
		public bool IsPaddingInvalid => ReturnCode == 0x57;
	}

	// Hand-written DCE/RPC proxy for MS-BKRP (BackupKey Remote Protocol).
	// Follows the same pattern as the Animus IDL-generated proxies.
	//
	// IDL (simplified):
	//   DWORD BackuprKey(
	//     [in]           handle_t                          h,          // binding handle, not marshalled
	//     [in]           GUID                             *pguidActionAgent,   // ref pointer (no referent ID)
	//     [in, size_is(cbDataIn)] byte                    *pDataIn,
	//     [in]           DWORD                             cbDataIn,
	//     [out, size_is(,*pcbDataOut)] byte              **ppDataOut,
	//     [out]          DWORD                            *pcbDataOut,
	//     [in]           DWORD                             dwParam     // must be 0
	//   );
	internal sealed class BkrpProxy : RpcClientProxy, IRpcClientProxy
	{
		private static readonly Guid InterfaceUuidValue = new("3dde7c30-165d-11d1-ab8f-00805f14db40");
		private static readonly RpcVersion InterfaceVersionValue = new(1, 0);

		public override Guid InterfaceUuid => InterfaceUuidValue;
		public override RpcVersion InterfaceVersion => InterfaceVersionValue;
		public override Type InterfaceType => typeof(BkrpProxy);

		public async Task<BkrpCallResult> BackuprKeyAsync(
			Guid actionAgent,
			byte[]? dataIn,
			uint cbDataIn,
			CancellationToken cancellationToken)
		{
			IRpcRequestBuilder req = this.CreateRequest(0);
			IRpcEncoder encoder = req.StubData;

			// pguidActionAgent: reference pointer – GUID written inline (no referent ID)
			encoder.WriteValue(actionAgent);

			// pDataIn: [in, size_is(cbDataIn)] byte* — no referent ID on the wire.
			// Despite the IDL showing [unique], the actual MS-BKRP wire format treats this as
			// a bare conformant array (no referent ID). Adding a referent ID causes the server
			// to return RPC_X_BAD_STUB_DATA (the server's NDR layer rejects it).
			// Conformant array: max_count followed immediately by the bytes.
			var effectiveData = dataIn ?? Array.Empty<byte>();
			encoder.WriteArrayHeader<byte>(effectiveData);
			for (int i = 0; i < effectiveData.Length; i++)
				encoder.WriteValue(effectiveData[i]);

			// cbDataIn
			encoder.WriteValue(cbDataIn);

			// dwParam must be 0
			encoder.WriteValue(0u);

			IRpcDecoder decoder = await this.SendRequestAsync(req, cancellationToken).ConfigureAwait(false);

			// Capture raw stub bytes BEFORE reading (position is 0 at this point)
			var stubReader = decoder.GetStubData();
			var diagBytes = stubReader.Remaining.ToArray();

			// ppDataOut: outer ref pointer is not on wire; read the inner unique pointer referent
			var innerRefId = decoder.ReadReferentId();
			byte[]? dataOut = null;
			if (innerRefId != 0)
			{
				var arr = decoder.ReadArrayHeader<byte>();
				for (int i = 0; i < arr.Length; i++)
					arr[i] = decoder.ReadChar();
				dataOut = arr;
			}

			// pcbDataOut (ref pointer – just the DWORD value)
			var cbDataOut = decoder.ReadUInt32();

			// return code (Win32 DWORD)
			var retval = decoder.ReadUInt32();

			return new BkrpCallResult
			{
				ReturnCode = retval,
				DataOut = dataOut,
				DataOutLength = cbDataOut,
				DiagStubBytes = diagBytes
			};
		}
	}

	// Thin client wrapper around BkrpProxy — mirrors the RpcServiceClient<T> pattern.
	internal sealed class BkrpClient : RpcServiceClient<BkrpProxy>
	{
		public const string BkrpPipeName = "protected_storage";

		// [MS-BKRP] § 2.1 – must use Kerberos + privacy-level encryption
		public override string? WellKnownPipeName => BkrpPipeName;
		public override bool SupportsDynamicTcp => false;
		public override bool SupportsNdr64 => false;
		public override bool SupportsReauthOverNamedPipes => true;
		public override string? ServiceClass => ServiceClassNames.HostU;

		public Task<BkrpCallResult> BackuprKeyAsync(
			Guid actionAgent,
			byte[]? dataIn,
			uint cbDataIn,
			CancellationToken cancellationToken)
			=> this._proxy.BackuprKeyAsync(actionAgent, dataIn, cbDataIn, cancellationToken);
	}

	// Wraps an open, bound BkrpClient and its underlying SMB resources.
	public sealed class BkrpSession : IAsyncDisposable, IDisposable
	{
		internal BkrpSession(BkrpClient client, Smb2TreeConnect share, Stream stream)
		{
			this.Client = client ?? throw new ArgumentNullException(nameof(client));
			this._share = share ?? throw new ArgumentNullException(nameof(share));
			this._stream = stream ?? throw new ArgumentNullException(nameof(stream));
		}

		internal BkrpClient Client { get; }

		private readonly Smb2TreeConnect _share;
		private readonly Stream _stream;
		private bool _disposed;

		// Convenience: retrieve the DC's RSA backup-key certificate and extract modulus/exponent.
		// backupKeyGuid must be the GUID from DomainKeyBlock.BackupKeyGuid — the server locates
		// its stored backup key by matching this GUID in pDataIn ([MS-BKRP] §3.1.4.1.1).
		public async Task<BkrpPublicKeyInfo> GetBackupPublicKeyAsync(Guid backupKeyGuid, CancellationToken cancellationToken)
		{
			var guidBytes = new byte[16];
			backupKeyGuid.TryWriteBytes(guidBytes);

			var result = await this.Client.BackuprKeyAsync(
				BkrpActionGuids.RetrieveBackupKey,
				guidBytes,
				16,
				cancellationToken).ConfigureAwait(false);

			if (!result.IsSuccess)
			{
				// If 0x57, probe with the null GUID to distinguish "this specific key not in AD"
				// from "BKRP not working at all". Null GUID returns the DC's current backup key
				// ([MS-BKRP] §3.1.4.1.1) so success means the plumbing works but BackupKeyGuid
				// refers to a key that has been rotated out of AD on this DC.
				string? probeHint = null;
				if (result.ReturnCode == 0x57)
				{
					try
					{
						var probe = await this.Client.BackuprKeyAsync(
							BkrpActionGuids.RetrieveBackupKey,
							new byte[16],   // null GUID → return current backup key
							16,
							cancellationToken).ConfigureAwait(false);
						probeHint = probe.IsSuccess
							? $" Null-GUID probe succeeded (DC has a current backup key). " +
							  $"Requested GUID {backupKeyGuid:D} is not present in AD on this DC — " +
							  $"it may have been rotated. Check AD: Get-ADObject -Filter {{name -like \"BCKUPKEY*\"}} " +
							  $"-SearchBase \"CN=System,...\" -Properties objectGuid,name"
							: $" Null-GUID probe also failed (0x{probe.ReturnCode:x}) — DC has no backup keys.";
					}
					catch { /* best-effort probe */ }
				}

				var diag = result.DiagStubBytes;
				throw new InvalidOperationException(
					$"BackuprKey(RetrieveBackupKey) failed with Win32 error 0x{result.ReturnCode:x} " +
					$"for backup key GUID {backupKeyGuid:D}." +
					(probeHint ?? string.Empty) + " " +
					$"Response stub ({diag?.Length ?? 0} bytes): " +
					(diag != null ? BitConverter.ToString(diag) : "(null)"));
			}

			if (result.DataOut == null || result.DataOut.Length == 0)
				throw new InvalidDataException("BackuprKey returned no certificate data.");

			return BkrpPublicKeyInfo.FromCertificate(result.DataOut);
		}

		// Oracle query: returns true when PKCS#1 v1.5 padding is valid (0x0d or success),
		// false when padding is invalid (0x57).
		public async Task<BkrpCallResult> QueryOracleAsync(byte[] blob, CancellationToken cancellationToken)
			=> await this.Client.BackuprKeyAsync(
				BkrpActionGuids.RestoreKey,
				blob,
				(uint)blob.Length,
				cancellationToken).ConfigureAwait(false);

		public async ValueTask DisposeAsync()
		{
			if (this._disposed) return;
			this._disposed = true;
			try { this.Client.Dispose(); }
			finally
			{
				this._stream.Dispose();
				await this._share.DisposeAsync().ConfigureAwait(false);
			}
		}

		public void Dispose() => this.DisposeAsync().GetAwaiter().GetResult();
	}

	// RSA public key extracted from the DC's X.509 backup key certificate.
	public sealed class BkrpPublicKeyInfo
	{
		public System.Numerics.BigInteger Modulus { get; init; }
		public System.Numerics.BigInteger Exponent { get; init; }

		// Key size in bytes (= modulus byte length)
		public int KeySizeBytes { get; init; }

		// Parse a locally cached BK-{domain} file from the user's Protect directory.
		// Format: version(4) + cbCert(4) + header-data + DER-cert (last cbCert bytes).
		public static BkrpPublicKeyInfo FromBkFile(byte[] bkFileBytes)
		{
			if (bkFileBytes == null || bkFileBytes.Length < 8)
				throw new InvalidDataException("BK file is too short to contain a certificate.");

			var cbCert = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(bkFileBytes.AsSpan(4));
			if (cbCert == 0 || cbCert > (uint)(bkFileBytes.Length - 8))
				throw new InvalidDataException(
					$"BK file certificate length field (0x{cbCert:x}) is out of range for a {bkFileBytes.Length}-byte file.");

			var certOffset = bkFileBytes.Length - (int)cbCert;
			return FromCertificate(bkFileBytes[certOffset..]);
		}

		public static BkrpPublicKeyInfo FromCertificate(byte[] derCertificate)
		{
			var cert = new X509Certificate2(derCertificate);
			using var rsa = cert.GetRSAPublicKey()
				?? throw new InvalidDataException("DC backup certificate does not contain an RSA public key.");

			var rsaParams = rsa.ExportParameters(includePrivateParameters: false);

			if (rsaParams.Modulus == null || rsaParams.Exponent == null)
				throw new InvalidDataException("RSA parameters are incomplete.");

			// BigInteger: treat as unsigned big-endian (prepend 0x00 to avoid sign bit)
			var n = new System.Numerics.BigInteger(rsaParams.Modulus, isUnsigned: true, isBigEndian: true);
			var e = new System.Numerics.BigInteger(rsaParams.Exponent, isUnsigned: true, isBigEndian: true);

			return new BkrpPublicKeyInfo
			{
				Modulus = n,
				Exponent = e,
				KeySizeBytes = rsaParams.Modulus.Length
			};
		}
	}
}
