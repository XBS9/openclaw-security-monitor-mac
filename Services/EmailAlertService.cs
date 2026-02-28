using System.Net;
using System.Net.Mail;
using OpenClawSecurityMonitorMac.Models;

namespace OpenClawSecurityMonitorMac.Services;

/// <summary>
/// Sends email alerts via SMTP when the kill switch fires.
///
/// Uses System.Net.Mail (built-in to .NET 8). Credentials and host are
/// read from TraySettings and stored in ~/.openclaw/monitor-settings.json
/// (chmod 600 — protected to current user only).
///
/// Fire-and-forget; exceptions are silently swallowed because email delivery
/// is best-effort and must not interfere with the kill-switch flow.
/// </summary>
public class EmailAlertService
{
    private readonly Core.TraySettings _settings;

    public EmailAlertService(Core.TraySettings settings) => _settings = settings;

    public void SendAlert(SecurityEvent evt)
    {
        if (!_settings.EmailAlertsEnabled) return;
        if (string.IsNullOrWhiteSpace(_settings.SmtpHost)) return;
        if (string.IsNullOrWhiteSpace(_settings.AlertEmailTo)) return;
        _ = SendAsync(evt);
    }

    private async Task SendAsync(SecurityEvent evt)
    {
        try
        {
            var body =
                $"OpenClaw Security Monitor Alert\n" +
                $"================================\n" +
                $"Host:      {Environment.MachineName}\n" +
                $"User:      {Environment.UserName}\n" +
                $"Monitor:   {evt.Monitor}\n" +
                $"Trigger:   {evt.Trigger}\n" +
                $"Details:   {evt.Details}\n" +
                $"Action:    {evt.Action}\n" +
                $"Timestamp: {evt.Timestamp:yyyy-MM-dd HH:mm:ss zzz}";

            using var client = new SmtpClient(_settings.SmtpHost, _settings.SmtpPort)
            {
                EnableSsl      = _settings.SmtpSsl,
                DeliveryMethod = SmtpDeliveryMethod.Network,
                Timeout        = 15_000,
                Credentials    = string.IsNullOrEmpty(_settings.SmtpUser)
                    ? null
                    : new NetworkCredential(_settings.SmtpUser, _settings.SmtpPassword)
            };

            var from = string.IsNullOrWhiteSpace(_settings.SmtpFrom)
                ? $"openclaw@{Environment.MachineName}"
                : _settings.SmtpFrom;

            using var msg = new MailMessage(from, _settings.AlertEmailTo)
            {
                Subject = $"[OpenClaw Alert] {evt.Trigger}",
                Body    = body
            };

            await client.SendMailAsync(msg);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[EmailAlert] SendAsync failed: {ex.Message}");
        }
    }
}
