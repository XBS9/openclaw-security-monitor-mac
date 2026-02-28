using OpenClawSecurityMonitorMac.Models;

namespace OpenClawSecurityMonitorMac.Core;

/// <summary>
/// Abstraction over GatewayService to allow unit testing of KillSwitch
/// and any other component that drives the gateway without spawning real processes.
/// </summary>
public interface IGatewayService
{
    Task<GatewayStatus> GetStatusAsync();
    Task<bool> LockAsync();
    Task<bool> UnlockAsync();
    Task<bool> RestartAsync();
    Task<(bool Success, string Message)> SyncTokenAsync();
    Task<string> GetLogsAsync(int lines = 100);
}
