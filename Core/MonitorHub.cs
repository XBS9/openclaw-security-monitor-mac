namespace OpenClawSecurityMonitorMac.Core;

public enum MonitorState
{
    Starting,
    Ok,
    Warning,
    Alert
}

public class MonitorStatus
{
    public string Name { get; set; } = "";
    public MonitorState State { get; set; } = MonitorState.Starting;
    public string Detail { get; set; } = "Starting...";
    public DateTime? LastChecked { get; set; }
}

public class MonitorHub
{
    private readonly Dictionary<string, MonitorStatus> _statuses = new();
    private readonly object _lock = new();

    public event Action? Updated;

    public static readonly string Gateway         = "Gateway Health";
    public static readonly string FileIntegrity   = "File Integrity";
    public static readonly string AlertLog        = "Alert Log";
    public static readonly string Egress          = "Egress Rules";
    public static readonly string Patches         = "Auth Patches";
    public static readonly string Namespace       = "Namespace Isolation";
    public static readonly string Permissions     = "Config Permissions";
    public static readonly string Exposure        = "Network Exposure";
    public static readonly string TokenAge        = "Token Age";
    public static readonly string LaunchAgents      = "Launch Agents";
    public static readonly string BinaryIntegrity   = "Binary Integrity";
    public static readonly string TccPermissions    = "TCC Permissions";
    public static readonly string SudoLog           = "Sudo Activity";
    public static readonly string SystemPosture     = "System Posture";
    public static readonly string CronJobs          = "Cron Jobs";
    public static readonly string SystemExtensions  = "System Extensions";

    public MonitorHub()
    {
        Register(Gateway);
        Register(FileIntegrity);
        Register(AlertLog);
        Register(Egress);
        Register(Patches);
        Register(Namespace);
        Register(Permissions);
        Register(Exposure);
        Register(TokenAge);
        Register(LaunchAgents);
        Register(BinaryIntegrity);
        Register(TccPermissions);
        Register(SudoLog);
        Register(SystemPosture);
        Register(CronJobs);
        Register(SystemExtensions);
    }

    private void Register(string name)
    {
        _statuses[name] = new MonitorStatus { Name = name };
    }

    public void Report(string name, MonitorState state, string detail)
    {
        Action? handler;
        lock (_lock)
        {
            if (_statuses.TryGetValue(name, out var status))
            {
                status.State = state;
                status.Detail = detail;
                status.LastChecked = DateTime.Now;
            }
            handler = Updated;
        }
        handler?.Invoke();
    }

    public List<MonitorStatus> GetAll()
    {
        lock (_lock)
        {
            return _statuses.Values.ToList();
        }
    }
}
