namespace OpenClawSecurityMonitorMac.Models;

public class SecurityAlert
{
    public DateTime Timestamp { get; set; }
    public string Severity { get; set; } = "INFO";
    public string Message { get; set; } = "";
    public string Source { get; set; } = "";

    public override string ToString() =>
        $"[{Timestamp:yyyy-MM-dd HH:mm:ss}] [{Severity}] {Message}";
}
