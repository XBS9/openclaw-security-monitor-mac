using System.Collections.ObjectModel;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using OpenClawSecurityMonitorMac.Core;
using OpenClawSecurityMonitorMac.Services;

namespace OpenClawSecurityMonitorMac.ViewModels;

public partial class LogViewerViewModel : ObservableObject
{
    private readonly KillSwitch _killSwitch;
    private readonly GatewayService _gateway;

    [ObservableProperty]
    private string _searchText = "";

    [ObservableProperty]
    private string _gatewayLogs = "";

    [ObservableProperty]
    private int _selectedTab;

    public ObservableCollection<string> SecurityEvents { get; } = new();
    public ObservableCollection<string> FilteredEvents { get; } = new();

    public LogViewerViewModel(KillSwitch killSwitch, GatewayService gateway)
    {
        _killSwitch = killSwitch;
        _gateway = gateway;
        LoadEvents();
    }

    private void LoadEvents()
    {
        SecurityEvents.Clear();
        FilteredEvents.Clear();

        foreach (var evt in _killSwitch.Events)
        {
            var line = evt.ToString();
            SecurityEvents.Add(line);
            FilteredEvents.Add(line);
        }

        if (SecurityEvents.Count == 0)
            FilteredEvents.Add("No security events recorded.");
    }

    partial void OnSearchTextChanged(string value)
    {
        FilteredEvents.Clear();
        foreach (var evt in SecurityEvents)
        {
            if (string.IsNullOrEmpty(value) ||
                evt.Contains(value, StringComparison.OrdinalIgnoreCase))
            {
                FilteredEvents.Add(evt);
            }
        }
    }

    [RelayCommand]
    private void Refresh() => LoadEvents();

    [RelayCommand]
    private void ClearEvents()
    {
        SecurityEvents.Clear();
        FilteredEvents.Clear();
        FilteredEvents.Add("No security events recorded.");
    }

    [RelayCommand]
    private async Task LoadGatewayLogs()
    {
        GatewayLogs = "Loading...";
        GatewayLogs = await _gateway.GetLogsAsync(200);
    }
}
