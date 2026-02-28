using System.Net.Http;
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
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("OpenClawMonitor/1.5.2");
        _http.Timeout = TimeSpan.FromSeconds(15);
    }

    /// <summary>
    /// Checks the GitHub releases API for a newer version.
    /// Returns an UpdateInfo (version + DMG download URL) if one is available, otherwise null.
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

            // Find the DMG asset URL
            if (!root.TryGetProperty("assets", out var assets)) return null;
            foreach (var asset in assets.EnumerateArray())
            {
                var name = asset.GetProperty("name").GetString() ?? "";
                if (name.EndsWith(".dmg", StringComparison.OrdinalIgnoreCase))
                {
                    var url = asset.GetProperty("browser_download_url").GetString();
                    if (url != null)
                        return new UpdateInfo(tag, url);
                }
            }
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
            var fileName  = $"OpenClawMonitor-{info.Version}.dmg";
            var localPath = Path.Combine(Path.GetTempPath(), fileName);

            if (File.Exists(localPath))
                return localPath; // already cached

            using var client = new HttpClient();
            client.Timeout = TimeSpan.FromMinutes(5);
            client.DefaultRequestHeaders.UserAgent.ParseAdd("OpenClawMonitor/1.5.2");

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
