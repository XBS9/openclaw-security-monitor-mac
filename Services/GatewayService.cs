using OpenClawSecurityMonitorMac.Core;
using OpenClawSecurityMonitorMac.Models;

namespace OpenClawSecurityMonitorMac.Services;

/// <summary>
/// Controls and queries the OpenClaw gateway via launchctl (macOS launchd).
///
/// Mode detection mirrors the Windows version's InaccessiblePaths logic:
///   • Active plist contains "ProcessType" (hardened launchd marker) → Locked
///   • Active plist matches unlocked template exactly → Unlocked (score 6.7)
///   • Active plist exists, no hardening, not our template → Unlocked (no score)
///   • Plist file missing → Unknown
///
/// Plist files live in ~/Library/LaunchAgents/:
///   ai.openclaw.gateway.plist          — active (copy, not symlink)
///   ai.openclaw.gateway.hardened.plist — hardened template (score 3.3)
///   ai.openclaw.gateway.unlocked.plist — unlocked template (score 6.7)
/// </summary>
public class GatewayService
{
    private readonly ICommandService _cmd;
    private readonly TraySettings _settings;

    public GatewayService(ICommandService cmd, TraySettings settings)
    {
        _cmd = cmd;
        _settings = settings;
    }

    public async Task<GatewayStatus> GetStatusAsync()
    {
        var status = new GatewayStatus { Port = _settings.GatewayPort };
        var basePath = PathUtils.Expand(_settings.ServiceBasePath);
        var label    = _settings.GatewayLabel;

        // Escape dots so awk treats the label as a literal string, not a wildcard regex.
        var awkLabel = label.Replace(".", "\\.");
        var cmd =
            // PID line from launchctl list — "-" means not running
            $"PID=$(launchctl list 2>/dev/null | awk '/{awkLabel}/{{print $1}}'); " +
            "echo \"RUNNING=$([ -n \"$PID\" ] && [ \"$PID\" != \"-\" ] && echo yes || echo no)\"; " +
            // Uptime via ps if running
            "if [ -n \"$PID\" ] && [ \"$PID\" != \"-\" ]; then " +
            "  echo \"UPTIME=$(ps -o etime= -p \"$PID\" 2>/dev/null | tr -d ' ')\"; " +
            "fi; " +
            // Mode detection from active plist (filename = label + .plist)
            $"if [ ! -f \"{basePath}/{label}.plist\" ]; then echo MODE=unknown; " +
            $"elif grep -q 'ProcessType' \"{basePath}/{label}.plist\"; then echo MODE=locked; " +
            $"elif diff -q \"{basePath}/{label}.plist\" \"{basePath}/{label}.unlocked.plist\" >/dev/null 2>&1; then echo MODE=unlocked_known; " +
            $"else echo MODE=unlocked; fi";

        var (_, output, _) = await _cmd.RunAsync(cmd);
        if (string.IsNullOrEmpty(output)) return status;

        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            if (line.StartsWith("RUNNING="))
                status.IsRunning = line["RUNNING=".Length..].Trim() == "yes";
            else if (line.StartsWith("UPTIME=") && status.IsRunning)
            {
                var elapsed = line["UPTIME=".Length..].Trim();
                if (!string.IsNullOrWhiteSpace(elapsed))
                    status.Uptime = FormatUptime(elapsed);
            }
            else if (line.StartsWith("MODE="))
            {
                switch (line["MODE=".Length..].Trim())
                {
                    case "locked":
                        status.Mode = GatewayMode.Locked;
                        status.SecurityScore = 3.3;
                        break;
                    case "unlocked_known":
                        status.Mode = GatewayMode.Unlocked;
                        status.SecurityScore = 6.7;
                        break;
                    case "unlocked":
                        status.Mode = GatewayMode.Unlocked;
                        break;
                    default:
                        status.Mode = GatewayMode.Unknown;
                        break;
                }
            }
        }

        return status;
    }

    public async Task<bool> LockAsync()
    {
        var basePath = PathUtils.Expand(_settings.ServiceBasePath);
        var label    = _settings.GatewayLabel;
        var cmd =
            $"launchctl unload \"{basePath}/{label}.plist\" 2>/dev/null; " +
            $"cp \"{basePath}/{label}.hardened.plist\" \"{basePath}/{label}.plist\" && " +
            $"launchctl load \"{basePath}/{label}.plist\"";

        var (exitCode, _, _) = await _cmd.RunAsync(cmd);
        return exitCode == 0;
    }

    public async Task<bool> UnlockAsync()
    {
        var basePath = PathUtils.Expand(_settings.ServiceBasePath);
        var label    = _settings.GatewayLabel;
        var cmd =
            $"launchctl unload \"{basePath}/{label}.plist\" 2>/dev/null; " +
            $"cp \"{basePath}/{label}.unlocked.plist\" \"{basePath}/{label}.plist\" && " +
            $"launchctl load \"{basePath}/{label}.plist\"";

        var (exitCode, _, _) = await _cmd.RunAsync(cmd);
        return exitCode == 0;
    }

    public async Task<bool> RestartAsync()
    {
        var basePath = PathUtils.Expand(_settings.ServiceBasePath);
        var label    = _settings.GatewayLabel;
        var cmd =
            $"launchctl unload \"{basePath}/{label}.plist\" 2>/dev/null; " +
            $"launchctl load \"{basePath}/{label}.plist\"";

        var (exitCode, _, _) = await _cmd.RunAsync(cmd);
        return exitCode == 0;
    }

    public async Task<string> GetLogsAsync(int lines = 100)
    {
        lines = Math.Max(1, lines);
        // Try openclaw's own log file first, fall back to macOS log utility
        var home = "$HOME";
        var (_, output, _) = await _cmd.RunAsync(
            $"if [ -f {home}/.openclaw/logs/gateway.log ]; then " +
            $"  tail -n {lines} {home}/.openclaw/logs/gateway.log 2>/dev/null; " +
            $"elif [ -f {home}/.openclaw/logs/gateway.err.log ]; then " +
            $"  tail -n {lines} {home}/.openclaw/logs/gateway.err.log 2>/dev/null; " +
            $"else echo 'No gateway log found.'; " +
            $"fi");
        return output;
    }

    /// <summary>
    /// Converts ps etime format [[DD-]HH:]MM:SS to a human-readable uptime string.
    /// </summary>
    private static string FormatUptime(string etime)
    {
        // etime format: [[DD-]HH:]MM:SS
        try
        {
            int days = 0, hours = 0, minutes = 0;
            var parts = etime.Split(':');

            if (parts.Length == 3)
            {
                // HH:MM:SS or DD-HH:MM:SS
                var hourPart = parts[0];
                if (hourPart.Contains('-'))
                {
                    var dp = hourPart.Split('-');
                    days  = int.Parse(dp[0]);
                    hours = int.Parse(dp[1]);
                }
                else
                {
                    hours = int.Parse(hourPart);
                }
                minutes = int.Parse(parts[1]);
            }
            else if (parts.Length == 2)
            {
                // MM:SS
                minutes = int.Parse(parts[0]);
            }

            if (days >= 1) return $"{days}d {hours}h";
            if (hours >= 1) return $"{hours}h {minutes}m";
            return $"{minutes}m";
        }
        catch
        {
            return etime;
        }
    }
}
