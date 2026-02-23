using Avalonia;
using OpenClawSecurityMonitorMac;

// Ensure only one instance runs at a time
var mutex = new System.Threading.Mutex(true, "OpenClawSecurityMonitorMac_SingleInstance", out var isNewInstance);
if (!isNewInstance)
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
    mutex.ReleaseMutex();
    mutex.Dispose();
}

static AppBuilder BuildAvaloniaApp() =>
    AppBuilder.Configure<App>()
        .UsePlatformDetect()
        .WithInterFont()
        .LogToTrace();
