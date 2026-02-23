using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using OpenClawSecurityMonitorMac.Core;
using OpenClawSecurityMonitorMac.Services;

namespace OpenClawSecurityMonitorMac;

public partial class App : Application
{
    private TrayApplication? _trayApp;

    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.ShutdownMode = Avalonia.Controls.ShutdownMode.OnExplicitShutdown;

            var settings = TraySettings.Load();
            var bash = new DirectBashService
            {
                TimeoutSeconds = settings.CommandTimeoutSeconds
            };
            var gateway = new GatewayService(bash, settings);
            var killSwitch = new KillSwitch(gateway, settings);

            _trayApp = new TrayApplication(settings, bash, gateway, killSwitch);
            _trayApp.Initialize();

            desktop.ShutdownRequested += (_, _) => _trayApp?.Dispose();
        }

        base.OnFrameworkInitializationCompleted();
    }
}
