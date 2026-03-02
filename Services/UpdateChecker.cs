using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace OpenClawSecurityMonitorMac.Services;

/// <summary>
/// Holds information about an available update returned by UpdateChecker.CheckAsync.
/// </summary>
public record UpdateInfo(string Version, string DownloadUrl);

public static class UpdateChecker
{
    private static readonly HttpClient _http = new();

    static UpdateChecker()
    {
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("OpenClawSecurityMonitor/1.6.0");
        _http.Timeout = TimeSpan.FromSeconds(15);
    }

    /// <summary>
    /// Checks the GitHub releases API for a newer version.
    /// Returns an UpdateInfo (version + DMG download URL) if one is available, otherwise null.
    /// Picks the DMG matching the current CPU architecture (arm64 or x64).
    /// </summary>
    public static async Task<UpdateInfo?> CheckAsync(string currentVersion)
    {
        try
        {
            var json = await _http.GetStringAsync(
                "https://api.github.com/repos/XBS9/openclaw-security-monitor-mac/releases/latest");

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            var tag = root.GetProperty("tag_name").GetString()?.TrimStart('v');
            if (tag == null) return null;

            if (!Version.TryParse(tag,            out var latest))  return null;
            if (!Version.TryParse(currentVersion, out var current)) return null;
            if (latest <= current) return null;

            // Pick the DMG that matches the running architecture
            var archSuffix = RuntimeInformation.ProcessArchitecture == Architecture.Arm64
                ? "-arm64.dmg"
                : "-x64.dmg";

            if (!root.TryGetProperty("assets", out var assets)) return null;

            string? fallbackUrl = null;
            foreach (var asset in assets.EnumerateArray())
            {
                var name = asset.GetProperty("name").GetString() ?? "";
                if (!name.EndsWith(".dmg", StringComparison.OrdinalIgnoreCase)) continue;
                var url = asset.GetProperty("browser_download_url").GetString();
                if (url == null) continue;
                if (name.EndsWith(archSuffix, StringComparison.OrdinalIgnoreCase))
                    return new UpdateInfo(tag, url);
                fallbackUrl ??= url; // keep first DMG as fallback if arch match not found
            }
            if (fallbackUrl != null)
                return new UpdateInfo(tag, fallbackUrl);
        }
        catch
        {
            // Network errors are silent — update check is best-effort
        }
        return null;
    }

    /// <summary>
    /// Downloads the DMG from UpdateInfo.DownloadUrl to the system temp directory.
    /// Returns the local file path, or null on failure.
    /// Skips download if the file is already cached.
    /// </summary>
    public static async Task<string?> DownloadAsync(UpdateInfo info, CancellationToken ct = default)
    {
        try
        {
            var archSuffix = RuntimeInformation.ProcessArchitecture == Architecture.Arm64
                ? "arm64" : "x64";
            var fileName  = $"OpenClawSecurityMonitor-{info.Version}-{archSuffix}.dmg";
            var localPath = Path.Combine(Path.GetTempPath(), fileName);

            if (File.Exists(localPath))
                return localPath; // already cached

            using var client = new HttpClient();
            client.Timeout = TimeSpan.FromMinutes(5);
            client.DefaultRequestHeaders.UserAgent.ParseAdd("OpenClawSecurityMonitor/1.6.0");

            var bytes = await client.GetByteArrayAsync(info.DownloadUrl, ct);
            await File.WriteAllBytesAsync(localPath, bytes, ct);
            return localPath;
        }
        catch
        {
            return null;
        }
    }
}
