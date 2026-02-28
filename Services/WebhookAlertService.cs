using System.Net.Http;
using System.Text;
using System.Text.Json;
using OpenClawSecurityMonitorMac.Core;
using OpenClawSecurityMonitorMac.Models;

namespace OpenClawSecurityMonitorMac.Services;

/// <summary>
/// Posts a JSON alert to a configured webhook URL when the kill switch fires.
/// Designed for n8n, Slack incoming webhooks, or any HTTP endpoint.
///
/// Fire-and-forget: webhook failures are silently swallowed so they never
/// block or delay the kill switch response.
///
/// Payload:
///   { source, host, username, trigger, details, timestamp }
/// </summary>
public class WebhookAlertService
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(10) };

    private readonly TraySettings _settings;

    public WebhookAlertService(TraySettings settings)
    {
        _settings = settings;
    }

    public void SendAlert(SecurityEvent evt)
    {
        if (!_settings.WebhookAlertsEnabled || string.IsNullOrWhiteSpace(_settings.WebhookAlertUrl))
            return;

        _ = SendAsync(evt);
    }

    private async Task SendAsync(SecurityEvent evt)
    {
        try
        {
            var payload = new
            {
                source    = "OpenClawSecurityMonitor",
                host      = Environment.MachineName,
                username  = Environment.UserName,
                trigger   = evt.Trigger,
                monitor   = evt.Monitor,
                details   = evt.Details,
                action    = evt.Action,
                timestamp = evt.Timestamp.ToString("o")
            };

            var json    = JsonSerializer.Serialize(payload);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            await Http.PostAsync(_settings.WebhookAlertUrl, content);
        }
        catch
        {
            // Best-effort — webhook failures must never disrupt the kill switch
        }
    }
}
