using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Management.Automation.Provider;
using System.Text;
using Titanis.Smb2;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal sealed class SmbContentReader : IContentReader
	{
		private readonly Smb2FileStream _stream;
		private readonly Encoding _encoding;
		private readonly bool _raw;
		private StreamReader? _reader;
		private bool _completed;

		internal SmbContentReader(Smb2FileStream stream, Encoding encoding, bool raw)
		{
			if (stream is null) throw new ArgumentNullException(nameof(stream));
			if (encoding is null) throw new ArgumentNullException(nameof(encoding));

			this._stream = stream;
			this._encoding = encoding;
			this._raw = raw;
			this._reader = new StreamReader(stream, encoding, true, 4096, false);
		}

		public void Close()
		{
			Dispose();
		}

		public void Dispose()
		{
			this._reader?.Dispose();
			this._reader = null;
		}

		public IList Read(long readCount)
		{
			if (this._completed || this._reader is null)
				return Array.Empty<string>();

			if (this._raw)
			{
				string content = this._reader.ReadToEnd();
				this._completed = true;
				return new object[] { content };
			}

			if (readCount <= 0)
				readCount = long.MaxValue;

			List<string> lines = new List<string>();
			while (readCount-- > 0 && !this._reader.EndOfStream)
			{
				lines.Add(this._reader.ReadLine() ?? string.Empty);
			}

			if (this._reader.EndOfStream)
				this._completed = true;

			return lines;
		}

		public void Seek(long offset, SeekOrigin origin)
		{
			if (!this._stream.CanSeek)
				throw new NotSupportedException("The stream does not support seeking.");

			this._stream.Seek(offset, origin);
			this._reader?.DiscardBufferedData();
		}
	}
}
