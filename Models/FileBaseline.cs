namespace OpenClawSecurityMonitorMac.Models;

public class FileBaseline
{
    public string Path { get; set; } = "";
    public string Hash { get; set; } = "";
    public string Permissions { get; set; } = "";
    public bool ShouldBeImmutable { get; set; }
    public bool IsImmutable { get; set; }
    public bool IsCritical { get; set; }
}
