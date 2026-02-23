using System.Net.Http;
using System.Text.Json;

namespace OpenClawSecurityMonitorMac.Services;

public static class UpdateChecker
{
    private static readonly HttpClient _http = new();

    static UpdateChecker()
    {
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("OpenClawMonitor/1.5.2");
        _http.Timeout = TimeSpan.FromSeconds(10);
    }

    /// <summary>
    /// Returns the newer version tag string if one is available, otherwise null.
    /// </summary>
    public static async Task<string?> CheckAsync(string currentVersion)
    {
        try
        {
            var json = await _http.GetStringAsync(
                "https://api.github.com/repos/XBS9/openclaw-security-monitor-mac/releases/latest");
            using var doc = JsonDocument.Parse(json);
            var tag = doc.RootElement.GetProperty("tag_name").GetString()?.TrimStart('v');
            if (tag != null
                && Version.TryParse(tag, out var latest)
                && Version.TryParse(currentVersion, out var current)
                && latest > current)
            {
                return tag;
            }
        }
        catch
        {
            // Network errors are silent — update check is best-effort
        }
        return null;
    }
}
