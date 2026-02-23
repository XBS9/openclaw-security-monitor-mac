using System.Diagnostics;

namespace OpenClawSecurityMonitorMac.Services;

/// <summary>
/// Executes bash commands directly on the local macOS system.
/// Replaces WslCommandService (Windows-only) — no WSL layer required.
/// Uses /bin/bash with -c so all commands run in a full shell environment.
/// </summary>
public class DirectBashService : ICommandService
{
    private static readonly string BashPath = "/bin/bash";

    private int _timeoutSeconds = 30;

    public int TimeoutSeconds
    {
        get => _timeoutSeconds;
        set => _timeoutSeconds = value;
    }

    public async Task<(int ExitCode, string Output, string Error)> RunAsync(
        string bashCommand, string? stdinInput = null)
    {
        var psi = new ProcessStartInfo
        {
            FileName = BashPath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = stdinInput != null,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        // Pass HOME so ~ expansion in bash works correctly
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        psi.Environment["HOME"] = home;

        // Inherit PATH from current environment so npm, openclaw, etc. resolve
        var path = Environment.GetEnvironmentVariable("PATH") ?? "/usr/local/bin:/usr/bin:/bin";
        // Prepend common macOS package manager paths that may not be in launchd's PATH
        psi.Environment["PATH"] = $"/opt/homebrew/bin:/usr/local/bin:{path}";

        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add(bashCommand);

        using var process = new Process { StartInfo = psi };
        process.Start();

        if (stdinInput != null)
        {
            await process.StandardInput.WriteAsync(stdinInput);
            process.StandardInput.Close();
        }

        var outputTask = process.StandardOutput.ReadToEndAsync();
        var errorTask  = process.StandardError.ReadToEndAsync();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(_timeoutSeconds));
        try
        {
            await process.WaitForExitAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            try { await process.WaitForExitAsync(); } catch { }
            try { await Task.WhenAll(outputTask, errorTask).WaitAsync(TimeSpan.FromSeconds(2)); } catch { }
            return (-1, "", $"Command timed out after {_timeoutSeconds}s");
        }

        return (process.ExitCode, (await outputTask).Trim(), (await errorTask).Trim());
    }

    public async Task<bool> IsAvailableAsync()
    {
        try
        {
            var (exitCode, output, _) = await RunAsync("echo ok");
            return exitCode == 0 && output.Trim() == "ok";
        }
        catch
        {
            return false;
        }
    }
}
