namespace OpenClawSecurityMonitorMac.Services;

public interface ICommandService
{
    Task<(int ExitCode, string Output, string Error)> RunAsync(string bashCommand, string? stdinInput = null);
    Task<bool> IsAvailableAsync();
}
