using OpenClawSecurityMonitorMac.Models;
using OpenClawSecurityMonitorMac.Services;

namespace OpenClawSecurityMonitorMac.Core;

public class KillSwitch
{
    private readonly GatewayService _gateway;
    private readonly TraySettings _settings;
    private readonly object _lock = new();
    private bool _engaged;

    public event Action<SecurityEvent>? Triggered;
    public bool IsEngaged => _engaged;

    private readonly List<SecurityEvent> _events = new();
    public IReadOnlyList<SecurityEvent> Events
    {
        get { lock (_lock) return _events.ToList(); }
    }

    public int UnreviewedCount { get; private set; }

    public KillSwitch(GatewayService gateway, TraySettings settings)
    {
        _gateway = gateway;
        _settings = settings;
    }

    public async Task FireAsync(string monitor, string trigger, string details)
    {
        var evt = new SecurityEvent
        {
            Timestamp = DateTime.Now,
            Monitor = monitor,
            Trigger = trigger,
            Details = details,
            Action = "KILL_SWITCH: Gateway locked"
        };

        Action<SecurityEvent>? handler;
        lock (_lock)
        {
            _events.Add(evt);
            _engaged = true;
            UnreviewedCount++;
            handler = Triggered;
        }

        LogEvent(evt);

        // Fire event immediately so UI updates before waiting for lock
        handler?.Invoke(evt);

        var locked = await _gateway.LockAsync();
        if (!locked)
        {
            await Task.Delay(2000);
            locked = await _gateway.LockAsync();
            if (!locked)
            {
                LogEvent(new SecurityEvent
                {
                    Timestamp = DateTime.Now,
                    Monitor = "KillSwitch",
                    Trigger = "LockAsync FAILED",
                    Details = "Gateway could not be locked after kill switch trigger — manual intervention required",
                    Action = "LOCK_FAILED"
                });
            }
        }
    }

    public void ClearAlerts()
    {
        lock (_lock)
        {
            UnreviewedCount = 0;
        }
    }

    public void Disengage()
    {
        lock (_lock)
        {
            _engaged = false;
        }
    }

    private void LogEvent(SecurityEvent evt)
    {
        try
        {
            var logPath = GetLogPath();
            var logDir = Path.GetDirectoryName(logPath);
            if (logDir != null)
                Directory.CreateDirectory(logDir);

            lock (_lock)
            {
                File.AppendAllText(logPath, evt.ToString() + Environment.NewLine);
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[KillSwitch] LogEvent failed: {ex.Message}");
        }
    }

    private static string GetLogPath()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return Path.Combine(home, ".openclaw", "security-tray.log");
    }
}
