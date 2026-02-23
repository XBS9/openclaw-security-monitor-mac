using System.Text.Json;
using System.Text.Json.Serialization;
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
        _gateway  = gateway;
        _settings = settings;
        LoadState();
    }

    public async Task FireAsync(string monitor, string trigger, string details)
    {
        var evt = new SecurityEvent
        {
            Timestamp = DateTime.Now,
            Monitor   = monitor,
            Trigger   = trigger,
            Details   = details,
            Action    = "KILL_SWITCH: Gateway locked"
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
        PersistState();

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
                    Monitor   = "KillSwitch",
                    Trigger   = "LockAsync FAILED",
                    Details   = "Gateway could not be locked after kill switch trigger — manual intervention required",
                    Action    = "LOCK_FAILED"
                });
            }
        }
    }

    public void ClearAlerts()
    {
        lock (_lock) { UnreviewedCount = 0; }
        PersistState();
    }

    public void Disengage()
    {
        lock (_lock) { _engaged = false; }
        PersistState();
    }

    // ── Persistence ────────────────────────────────────────────────────────────

    private record StateFile(
        [property: JsonPropertyName("engaged")]        bool Engaged,
        [property: JsonPropertyName("unreviewedCount")] int UnreviewedCount,
        [property: JsonPropertyName("events")]         List<SecurityEventDto> Events);

    private record SecurityEventDto(
        [property: JsonPropertyName("timestamp")] DateTime Timestamp,
        [property: JsonPropertyName("monitor")]   string Monitor,
        [property: JsonPropertyName("trigger")]   string Trigger,
        [property: JsonPropertyName("details")]   string Details,
        [property: JsonPropertyName("action")]    string Action);

    private string StatePath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                     ".openclaw", "kill-switch-state.json");

    private void LoadState()
    {
        try
        {
            if (!File.Exists(StatePath)) return;
            var json  = File.ReadAllText(StatePath);
            var state = JsonSerializer.Deserialize<StateFile>(json);
            if (state == null) return;
            lock (_lock)
            {
                _engaged        = state.Engaged;
                UnreviewedCount = state.UnreviewedCount;
                _events.AddRange(state.Events.Select(e => new SecurityEvent
                {
                    Timestamp = e.Timestamp,
                    Monitor   = e.Monitor,
                    Trigger   = e.Trigger,
                    Details   = e.Details,
                    Action    = e.Action
                }));
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[KillSwitch] LoadState failed: {ex.Message}");
        }
    }

    private void PersistState()
    {
        try
        {
            List<SecurityEventDto> dtos;
            bool engaged;
            int unreviewed;
            lock (_lock)
            {
                engaged     = _engaged;
                unreviewed  = UnreviewedCount;
                dtos        = _events.TakeLast(200).Select(e => new SecurityEventDto(
                    e.Timestamp, e.Monitor, e.Trigger, e.Details, e.Action)).ToList();
            }
            var state = new StateFile(engaged, unreviewed, dtos);
            var json  = JsonSerializer.Serialize(state, new JsonSerializerOptions { WriteIndented = true });
            var dir   = Path.GetDirectoryName(StatePath)!;
            Directory.CreateDirectory(dir);
            File.WriteAllText(StatePath, json);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[KillSwitch] PersistState failed: {ex.Message}");
        }
    }

    // ── Log (append-only human-readable) ───────────────────────────────────────

    private void LogEvent(SecurityEvent evt)
    {
        try
        {
            var logPath = PathUtils.ExpandFull(_settings.TrayLogPath);
            var logDir  = Path.GetDirectoryName(logPath);
            if (logDir != null) Directory.CreateDirectory(logDir);
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
}
