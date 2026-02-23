using System.Collections.ObjectModel;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using OpenClawSecurityMonitorMac.Services;

namespace OpenClawSecurityMonitorMac.ViewModels;

public partial class PatchViewModel : ObservableObject
{
    private readonly AutoPatchService _patchService;

    [ObservableProperty]
    private string _version = "Checking...";

    [ObservableProperty]
    private string _patchStatus = "Checking...";

    [ObservableProperty]
    private bool _isRunning;

    [ObservableProperty]
    private bool _canRunPatch = true;

    public ObservableCollection<string> LogLines { get; } = new();

    public PatchViewModel(AutoPatchService patchService)
    {
        _patchService = patchService;
        _patchService.Progress += OnProgress;
        _ = LoadStatusAsync();
    }

    private void OnProgress(string message)
    {
        Dispatcher.UIThread.InvokeAsync(() => LogLines.Add(message));
    }

    private async Task LoadStatusAsync()
    {
        try
        {
            Version = await _patchService.GetOpenClawVersionAsync();
        }
        catch
        {
            Version = "Error checking version";
        }
        PatchStatus = "Ready";
    }

    public void Cleanup()
    {
        _patchService.Progress -= OnProgress;
    }

    [RelayCommand]
    private async Task RunPatch()
    {
        if (IsRunning) return;

        IsRunning = true;
        CanRunPatch = false;
        LogLines.Clear();
        PatchStatus = "Running...";

        try
        {
            var (success, _) = await _patchService.RunPatchAsync();
            PatchStatus = success ? "Patches applied successfully" : "Patching completed with errors";
        }
        catch (Exception ex)
        {
            PatchStatus = $"Error: {ex.Message}";
            LogLines.Add($"Exception: {ex.Message}");
        }
        finally
        {
            IsRunning = false;
            CanRunPatch = true;
        }
    }
}
