namespace OpenClawSecurityMonitorMac.Models;

public enum GatewayMode
{
    Unknown,
    Locked,
    Unlocked
}

public class GatewayStatus
{
    public bool IsRunning { get; set; }
    public GatewayMode Mode { get; set; } = GatewayMode.Unknown;
    public string Uptime { get; set; } = "";
    public double SecurityScore { get; set; }
    public int Port { get; set; } = 18789;
}
