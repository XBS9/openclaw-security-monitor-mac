using Avalonia;
using OpenClawSecurityMonitorMac;

// Single-instance enforcement via exclusive file lock.
// The OS releases the lock automatically if the process crashes or is killed,
// so stale locks are never left behind.
var lockPath = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
    ".openclaw", "monitor.lock");

Directory.CreateDirectory(Path.GetDirectoryName(lockPath)!);

FileStream? lockFile = null;
try
{
    lockFile = new FileStream(lockPath, FileMode.OpenOrCreate,
                              FileAccess.ReadWrite, FileShare.None);
    // Write our PID so it's easy to identify via `cat ~/.openclaw/monitor.lock`
    lockFile.SetLength(0);
    var pidBytes = System.Text.Encoding.UTF8.GetBytes(Environment.ProcessId.ToString());
    lockFile.Write(pidBytes);
    lockFile.Flush();
}
catch (IOException)
{
    Console.Error.WriteLine("OpenClaw Security Monitor is already running.");
    return 1;
}

try
{
    return BuildAvaloniaApp().StartWithClassicDesktopLifetime(args, Avalonia.Controls.ShutdownMode.OnExplicitShutdown);
}
finally
{
    lockFile.Close();
    try { File.Delete(lockPath); } catch { /* best-effort */ }
}

static AppBuilder BuildAvaloniaApp() =>
    AppBuilder.Configure<App>()
        .UsePlatformDetect()
        .WithInterFont()
        .LogToTrace();
