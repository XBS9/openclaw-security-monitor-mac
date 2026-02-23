using Avalonia.Controls;
using Avalonia.Interactivity;

namespace OpenClawSecurityMonitorMac.Views;

public partial class LogViewerWindow : Window
{
    public LogViewerWindow()
    {
        InitializeComponent();
    }

    private void CloseButton_Click(object? sender, RoutedEventArgs e) => Close();
}
