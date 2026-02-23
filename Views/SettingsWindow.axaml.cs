using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
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
        vm.PathWarning    += msg => ShowPathWarning(msg);
        WireButtons();
    }

    private void WireButtons()
    {
        this.FindControl<Button>("BrowseNpmBtn")!.Click    += async (_, _) => await BrowseFolder("NpmGlobalPath");
        this.FindControl<Button>("BrowseConfigBtn")!.Click += async (_, _) => await BrowseFile("OpenClawConfigPath", "openclaw.json");
        this.FindControl<Button>("BrowseEnvBtn")!.Click    += async (_, _) => await BrowseFile("GatewayEnvPath", "gateway.env");
        this.FindControl<Button>("BrowseLogBtn")!.Click    += async (_, _) => await BrowseFile("SecurityAlertsLogPath", "security-alerts.log");
    }

    private async Task BrowseFolder(string vmProperty)
    {
        var results = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title       = "Select folder",
            AllowMultiple = false
        });
        if (results.Count > 0 && DataContext is SettingsViewModel vm)
            SetVmPath(vm, vmProperty, results[0].Path.LocalPath);
    }

    private async Task BrowseFile(string vmProperty, string suggestedName)
    {
        var results = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title          = $"Select {suggestedName}",
            AllowMultiple  = false,
            SuggestedFileName = suggestedName
        });
        if (results.Count > 0 && DataContext is SettingsViewModel vm)
            SetVmPath(vm, vmProperty, results[0].Path.LocalPath);
    }

    private static void SetVmPath(SettingsViewModel vm, string property, string path)
    {
        switch (property)
        {
            case "NpmGlobalPath":        vm.NpmGlobalPath        = path; break;
            case "OpenClawConfigPath":   vm.OpenClawConfigPath   = path; break;
            case "GatewayEnvPath":       vm.GatewayEnvPath       = path; break;
            case "SecurityAlertsLogPath":vm.SecurityAlertsLogPath = path; break;
        }
    }

    private void ShowPathWarning(string message)
    {
        if (this.FindControl<TextBlock>("PathWarningText") is TextBlock tb)
            tb.Text = message;
    }
}
