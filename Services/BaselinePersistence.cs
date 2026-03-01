using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using OpenClawSecurityMonitorMac.Models;

[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("OpenClawSecurityMonitorMac.Tests")]

namespace OpenClawSecurityMonitorMac.Services;

/// <summary>
/// Persists monitor baselines to ~/.openclaw/baselines/ as JSON files with SHA-256
/// integrity sidecars, using the same pattern as TraySettings.
///
/// Tamper detection: each baseline JSON is hashed and stored in a .integrity sidecar.
/// On load, the hash is verified with a fixed-time comparison. A mismatch means the
/// file was modified without updating the sidecar — treat it as first run.
///
/// Files are chmod 600 after every write (current user only).
/// </summary>
public static class BaselinePersistence
{
    /// <summary>
    /// Set by unit tests to redirect all baseline I/O to an isolated temp directory.
    /// Must be null in production. Protected by <c>[Collection("NoParallel")]</c>
    /// on the test classes to prevent concurrent access from multiple test classes.
    /// </summary>
    internal static string? TestBaselineDir { get; set; }

    private static string BaselineDir =>
        TestBaselineDir ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".openclaw", "baselines");

    // -------------------------------------------------------------------------
    // HashSet<string> baselines
    // (LaunchAgentScanMonitor, CronJobMonitor, SystemExtensionMonitor, SystemPostureMonitor)
    // -------------------------------------------------------------------------

    public enum LoadResult { Ok, NotFound, Tampered }

    /// <summary>
    /// Loads a baseline from disk. Returns NotFound (no file), Tampered, or Ok.
    /// The HashSet uses Ordinal string comparer to match on-disk filenames exactly.
    /// </summary>
    public static LoadResult TryLoad(string name, out HashSet<string>? result)
    {
        result = null;
        var path          = FilePath(name);
        var integrityPath = path + ".integrity";

        if (!File.Exists(path)) return LoadResult.NotFound;

        try
        {
            var json = File.ReadAllText(path);

            if (File.Exists(integrityPath))
            {
                var storedHex = File.ReadAllText(integrityPath).Trim();
                if (!VerifyHash(json, storedHex))
                    return LoadResult.Tampered;
            }

            var list = JsonSerializer.Deserialize<List<string>>(json);
            result = new HashSet<string>(list ?? [], StringComparer.Ordinal);
            return LoadResult.Ok;
        }
        catch
        {
            return LoadResult.NotFound;
        }
    }

    /// <summary>Saves a baseline to disk with integrity sidecar.</summary>
    public static void Save(string name, HashSet<string> baseline)
    {
        try
        {
            Directory.CreateDirectory(BaselineDir);
            var path          = FilePath(name);
            var integrityPath = path + ".integrity";

            var json = JsonSerializer.Serialize(baseline.ToList());
            File.WriteAllText(path, json);
            File.WriteAllText(integrityPath, ComputeHash(json));
            Chmod600(path);
            Chmod600(integrityPath);
        }
        catch { }
    }

    // -------------------------------------------------------------------------
    // Dictionary<string, FileBaseline> baselines (FileIntegrityMonitor)
    // -------------------------------------------------------------------------

    /// <summary>
    /// Loads a file-integrity baseline from disk.
    /// </summary>
    public static LoadResult TryLoadDict(string name, out Dictionary<string, FileBaseline>? result)
    {
        result = null;
        var path          = FilePath(name);
        var integrityPath = path + ".integrity";

        if (!File.Exists(path)) return LoadResult.NotFound;

        try
        {
            var json = File.ReadAllText(path);

            if (File.Exists(integrityPath))
            {
                var storedHex = File.ReadAllText(integrityPath).Trim();
                if (!VerifyHash(json, storedHex))
                    return LoadResult.Tampered;
            }

            result = JsonSerializer.Deserialize<Dictionary<string, FileBaseline>>(json)
                     ?? new Dictionary<string, FileBaseline>();
            return LoadResult.Ok;
        }
        catch
        {
            return LoadResult.NotFound;
        }
    }

    /// <summary>Saves a file-integrity baseline to disk with integrity sidecar.</summary>
    public static void SaveDict(string name, Dictionary<string, FileBaseline> baseline)
    {
        try
        {
            Directory.CreateDirectory(BaselineDir);
            var path          = FilePath(name);
            var integrityPath = path + ".integrity";

            var json = JsonSerializer.Serialize(baseline);
            File.WriteAllText(path, json);
            File.WriteAllText(integrityPath, ComputeHash(json));
            Chmod600(path);
            Chmod600(integrityPath);
        }
        catch { }
    }

    // -------------------------------------------------------------------------
    // Utilities
    // -------------------------------------------------------------------------

    private static string FilePath(string name) =>
        Path.Combine(BaselineDir, name + ".json");

    private static string ComputeHash(string json)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(json));
        return Convert.ToHexString(hash);
    }

    /// <summary>
    /// Constant-time hash comparison. Returns true if json matches storedHex.
    /// If the sidecar hex is corrupt/unreadable, returns true to avoid blocking loads
    /// (the sidecar missing is treated as unprotected rather than tampered).
    /// </summary>
    private static bool VerifyHash(string json, string storedHex)
    {
        try
        {
            var stored  = Convert.FromHexString(storedHex);
            var current = SHA256.HashData(Encoding.UTF8.GetBytes(json));
            return CryptographicOperations.FixedTimeEquals(stored, current);
        }
        catch
        {
            return true; // corrupt sidecar — allow load rather than block
        }
    }

    private static void Chmod600(string filePath)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName        = "/bin/chmod",
                ArgumentList    = { "600", filePath },
                UseShellExecute = false,
                CreateNoWindow  = true
            };
            using var p = System.Diagnostics.Process.Start(psi);
            p?.WaitForExit(2000);
        }
        catch { }
    }
}
