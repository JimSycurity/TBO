using System;
using System.Collections;
using System.Globalization;
using System.IO;
using System.Management.Automation.Provider;
using System.Text;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal sealed class SmbContentWriter : IContentWriter
	{
		private readonly Stream _stream;
		private readonly StreamWriter _writer;
		private readonly bool _noNewline;
		private bool _disposed;

		internal SmbContentWriter(Stream stream, Encoding encoding, bool noNewline)
		{
			if (stream is null) throw new ArgumentNullException(nameof(stream));
			if (encoding is null) throw new ArgumentNullException(nameof(encoding));

			this._stream = stream;
			this._writer = new StreamWriter(stream, encoding, 4096, false);
			this._noNewline = noNewline;
		}

		public void Close()
		{
			Dispose();
		}

		public void Dispose()
		{
			if (this._disposed)
				return;
			this._disposed = true;
			this._writer.Dispose();
		}

		public IList Write(IList content)
		{
			if (this._disposed)
				throw new ObjectDisposedException(nameof(SmbContentWriter));

			if (content == null || content.Count == 0)
				return Array.Empty<object>();

			foreach (var item in content)
			{
				var value = Convert.ToString(item, CultureInfo.CurrentCulture) ?? string.Empty;
				if (this._noNewline)
					this._writer.Write(value);
				else
					this._writer.WriteLine(value);
			}

			this._writer.Flush();
			return content;
		}

		public void Seek(long offset, SeekOrigin origin)
		{
			if (!this._stream.CanSeek)
				throw new NotSupportedException("The stream does not support seeking.");

			this._stream.Seek(offset, origin);
		}
	}
}
