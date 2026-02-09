using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace Titanis.Tbo.Smb2.PowerShell
{
	/// <summary>
	/// Initializes SQLitePCL so Microsoft.Data.Sqlite can load its bundled native provider (e_sqlite3).
	/// </summary>
	/// <remarks>
	/// Without this, Microsoft.Data.Sqlite may attempt to P/Invoke a system sqlite3 library, which is not
	/// present by default on Windows and causes DllNotFoundException at runtime.
	/// </remarks>
	internal static class SqliteBootstrap
	{
		private static int _initialized;

		private static void TryLoadBundledNativeProvider(Action<string>? logDiagnostic)
		{
			// PowerShell loads this as a DLL module; the native asset is shipped in the `runtimes/` folder.
			// DllImport does not probe that folder by default, so we proactively load the correct native DLL.
			var asmPath = typeof(SqliteBootstrap).Assembly.Location;
			if (string.IsNullOrWhiteSpace(asmPath))
				return;

			var moduleDir = Path.GetDirectoryName(asmPath);
			if (string.IsNullOrWhiteSpace(moduleDir))
				return;

			if (OperatingSystem.IsWindows())
			{
				const string dllName = "e_sqlite3.dll";

				// If the native DLL was copied next to the module, nothing to do.
				if (File.Exists(Path.Combine(moduleDir, dllName)))
					return;

				var rid = RuntimeInformation.ProcessArchitecture switch
				{
					Architecture.X64 => "win-x64",
					Architecture.X86 => "win-x86",
					Architecture.Arm64 => "win-arm64",
					Architecture.Arm => "win-arm",
					_ => null
				};

				if (rid == null)
					return;

				var nativePath = Path.Combine(moduleDir, "runtimes", rid, "native", dllName);
				if (!File.Exists(nativePath))
					return;

				NativeLibrary.Load(nativePath);
				logDiagnostic?.Invoke($"TBO: Loaded native SQLite provider from '{nativePath}'.");
			}
		}

		internal static void EnsureInitialized(Action<string>? logDiagnostic = null)
		{
			if (Volatile.Read(ref _initialized) == 1)
				return;

			if (Interlocked.CompareExchange(ref _initialized, 1, 0) != 0)
				return;

			try
			{
				TryLoadBundledNativeProvider(logDiagnostic);
				SQLitePCL.Batteries_V2.Init();
				logDiagnostic?.Invoke("TBO: SQLite provider initialized (SQLitePCL batteries_v2).");
			}
			catch
			{
				Volatile.Write(ref _initialized, 0);
				throw;
			}
		}
	}
}
