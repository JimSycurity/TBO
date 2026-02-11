using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using Titanis.Net;
using Titanis.Smb2;
using Titanis.Winterop.Security;
using Winterop = Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class FakeSmbFileSystem : ISmbFileSystem
	{
		private sealed class Node
		{
			public Node(ulong id, bool isDirectory, Winterop.FileAttributes attributes, Winterop.ReparseTag reparseTag)
			{
				this.Id = id;
				this.IsDirectory = isDirectory;
				this.Attributes = attributes;
				this.ReparseTag = reparseTag;
			}

			public ulong Id { get; }
			public bool IsDirectory { get; }
			public Winterop.FileAttributes Attributes { get; set; }
			public Winterop.ReparseTag ReparseTag { get; set; }
			public byte[]? Content { get; set; }
			public Dictionary<string, Node> Children { get; } = new(StringComparer.OrdinalIgnoreCase);
		}

		private readonly Dictionary<string, Node> _roots = new(StringComparer.OrdinalIgnoreCase);
		private ulong _nextNodeId = 1;

		public FakeSmbFileSystem AddDirectory(string uncPath)
		{
			return this.AddDirectory(uncPath, Winterop.FileAttributes.Directory, null);
		}

		public FakeSmbFileSystem AddDirectory(
			string uncPath,
			Winterop.FileAttributes attributes,
			Winterop.ReparseTag? reparseTag = null)
		{
			var path = UncPath.Parse(uncPath);
			var normalizedAttributes = attributes | Winterop.FileAttributes.Directory;
			var node = EnsureNode(path, isDirectory: true, normalizedAttributes, reparseTag);
			node.Attributes = normalizedAttributes;
			node.ReparseTag = reparseTag ?? default;
			return this;
		}

		public FakeSmbFileSystem AddFile(
			string uncPath,
			byte[] content,
			Winterop.FileAttributes attributes = Winterop.FileAttributes.Normal,
			Winterop.ReparseTag? reparseTag = null)
		{
			var path = UncPath.Parse(uncPath);
			var node = EnsureNode(path, isDirectory: false, attributes, reparseTag);
			node.Attributes = attributes;
			node.ReparseTag = reparseTag ?? default;
			node.Content = content ?? Array.Empty<byte>();
			return this;
		}

		public ISmbDirectory OpenDirectory(UncPath path, CancellationToken cancellationToken)
		{
			var node = GetNode(path);
			if (node == null)
				throw new Winterop.NtstatusException(Winterop.Ntstatus.STATUS_OBJECT_PATH_NOT_FOUND);
			if (!node.IsDirectory)
				throw new Winterop.NtstatusException(Winterop.Ntstatus.STATUS_NOT_A_DIRECTORY);
			return new FakeDirectory(path, node);
		}

		public ISmbFile OpenFileRead(UncPath path, CancellationToken cancellationToken)
		{
			var node = GetNode(path);
			if (node == null)
				throw new Winterop.NtstatusException(Winterop.Ntstatus.STATUS_OBJECT_NAME_NOT_FOUND);
			if (node.IsDirectory)
				throw new Winterop.NtstatusException(Winterop.Ntstatus.STATUS_FILE_IS_A_DIRECTORY);
			return new FakeFile(node.Content ?? Array.Empty<byte>());
		}

		private Node EnsureNode(
			UncPath path,
			bool isDirectory,
			Winterop.FileAttributes attributes,
			Winterop.ReparseTag? reparseTag)
		{
			var root = GetRoot(path);
			var relative = path.ShareRelativePath;
			if (string.IsNullOrWhiteSpace(relative))
				return root;

			var parts = relative.Split(new[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
			var current = root;
			for (int i = 0; i < parts.Length; i++)
			{
				var part = parts[i];
				var isLast = i == parts.Length - 1;
				if (!current.Children.TryGetValue(part, out var child))
				{
					var childIsDirectory = isLast ? isDirectory : true;
					var childAttributes = childIsDirectory ? Winterop.FileAttributes.Directory : attributes;
					var childReparseTag = isLast ? (reparseTag ?? default) : default;
					child = new Node(GetNextNodeId(), childIsDirectory, childAttributes, childReparseTag);
					current.Children[part] = child;
				}
				current = child;
			}

			if (!isDirectory && current.IsDirectory)
				current.Attributes = attributes;
			return current;
		}

		private Node? GetNode(UncPath path)
		{
			var root = TryGetRoot(path);
			if (root == null)
				return null;

			var relative = path.ShareRelativePath;
			if (string.IsNullOrWhiteSpace(relative))
				return root;

			var parts = relative.Split(new[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
			var current = root;
			foreach (var part in parts)
			{
				if (!current.Children.TryGetValue(part, out var child))
					return null;
				current = child;
			}

			return current;
		}

		private Node GetRoot(UncPath path)
		{
			var rootKey = $"\\\\{path.ServerName}\\{path.ShareName}";
			if (_roots.TryGetValue(rootKey, out var root))
				return root;
			root = new Node(GetNextNodeId(), true, Winterop.FileAttributes.Directory, default);
			_roots[rootKey] = root;
			return root;
		}

		private ulong GetNextNodeId()
		{
			return _nextNodeId++;
		}

		private Node? TryGetRoot(UncPath path)
		{
			var rootKey = $"\\\\{path.ServerName}\\{path.ShareName}";
			return _roots.TryGetValue(rootKey, out var root) ? root : null;
		}

		private sealed class FakeDirectory : ISmbDirectory
		{
			private readonly UncPath _path;
			private readonly Node _node;

			public FakeDirectory(UncPath path, Node node)
			{
				_path = path;
				_node = node;
			}

			public IReadOnlyList<Smb2DirEntry> QueryEntries(
				string pattern,
				Smb2Directory.Smb2DirQueryOptions options,
				SecurityInfo securityInfo,
				int bufferSize,
				CancellationToken cancellationToken)
			{
				var entries = new List<Smb2DirEntry>();
				foreach (var kvp in _node.Children.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
				{
					cancellationToken.ThrowIfCancellationRequested();
					var child = kvp.Value;
					var name = kvp.Key;

					if (!MatchesPattern(name, pattern))
						continue;

					entries.Add(new Smb2DirEntry
					{
						FileName = name,
						RelativePath = name,
						FileAttributes = child.Attributes,
						ReparseTag = child.ReparseTag,
						FileId = child.Id,
						Size = (ulong)(child.Content?.Length ?? 0),
						SizeOnDisk = (ulong)(child.Content?.Length ?? 0),
						CreationTime = DateTime.UtcNow,
						LastWriteTime = DateTime.UtcNow,
						LastAccessTime = DateTime.UtcNow,
						LastChangeTime = DateTime.UtcNow
					});
				}

				return entries;
			}

			private static bool MatchesPattern(string name, string pattern)
			{
				if (string.IsNullOrEmpty(pattern) || pattern == "*")
					return true;
				if (!pattern.Contains('*') && !pattern.Contains('?'))
					return string.Equals(name, pattern, StringComparison.OrdinalIgnoreCase);

				var escaped = System.Text.RegularExpressions.Regex.Escape(pattern);
				escaped = escaped.Replace("\\*", ".*").Replace("\\?", ".");
				var regex = new System.Text.RegularExpressions.Regex("^" + escaped + "$", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
				return regex.IsMatch(name);
			}

			public void Dispose()
			{
			}
		}

		private sealed class FakeFile : ISmbFile
		{
			private readonly byte[] _content;

			public FakeFile(byte[] content)
			{
				_content = content ?? Array.Empty<byte>();
			}

			public Stream OpenRead()
			{
				return new MemoryStream(_content, writable: false);
			}

			public long Length => _content.LongLength;

			public void Dispose()
			{
			}
		}
	}
}
