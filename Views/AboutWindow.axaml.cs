using System.Reflection;
using Avalonia.Controls;

namespace OpenClawSecurityMonitorMac.Views;

public partial class AboutWindow : Window
{
    public AboutWindow()
    {
        InitializeComponent();
        SetVersion();
    }

    private void SetVersion()
    {
        var v = Assembly.GetExecutingAssembly().GetName().Version;
        var versionText = v != null ? $"Version {v.Major}.{v.Minor}.{v.Build} (macOS)" : "Version —";
        if (this.FindControl<TextBlock>("VersionText") is TextBlock tb)
            tb.Text = versionText;
    }
}
