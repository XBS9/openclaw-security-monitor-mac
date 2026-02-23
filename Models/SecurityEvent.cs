namespace OpenClawSecurityMonitorMac.Models;

public class SecurityEvent
{
    public DateTime Timestamp { get; set; } = DateTime.Now;
    public string Trigger { get; set; } = "";
    public string Monitor { get; set; } = "";
    public string Action { get; set; } = "";
    public string Details { get; set; } = "";

    public override string ToString() =>
        $"[{Timestamp:yyyy-MM-dd HH:mm:ss}] [{Monitor}] {Trigger}: {Details} -> {Action}";
}
