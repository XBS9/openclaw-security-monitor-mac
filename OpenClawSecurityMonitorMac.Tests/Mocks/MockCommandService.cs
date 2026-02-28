using OpenClawSecurityMonitorMac.Services;

namespace OpenClawSecurityMonitorMac.Tests.Mocks;

/// <summary>
/// Fake ICommandService that returns pre-queued results without spawning any processes.
/// Enqueue results in the order they will be consumed. Falls back to (0, "", "") when
/// the queue is empty so tests don't have to account for every incidental command.
/// </summary>
public class MockCommandService : ICommandService
{
    private readonly Queue<(int ExitCode, string Output, string Error)> _results = new();

    /// <summary>All commands that were passed to RunAsync, in order.</summary>
    public List<string> CommandsRan { get; } = new();

    public void Enqueue(int exitCode = 0, string output = "", string error = "")
        => _results.Enqueue((exitCode, output, error));

    public void EnqueueMany(params (int exitCode, string output, string error)[] results)
    {
        foreach (var r in results) _results.Enqueue(r);
    }

    public Task<(int ExitCode, string Output, string Error)> RunAsync(string command, string? stdinInput = null)
    {
        CommandsRan.Add(command);
        return Task.FromResult(
            _results.TryDequeue(out var r) ? r : (0, "", ""));
    }

    public Task<bool> IsAvailableAsync() => Task.FromResult(true);
}
