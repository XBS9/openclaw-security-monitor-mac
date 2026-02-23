using Avalonia.Controls;
using OpenClawSecurityMonitorMac.ViewModels;

namespace OpenClawSecurityMonitorMac.Views;

public partial class SettingsWindow : Window
{
    public SettingsWindow()
    {
        InitializeComponent();
    }

    public SettingsWindow(SettingsViewModel vm) : this()
    {
        DataContext = vm;
        vm.CloseRequested += Close;
    }
}
