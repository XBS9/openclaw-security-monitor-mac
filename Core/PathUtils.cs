namespace OpenClawSecurityMonitorMac.Core;

public static class PathUtils
{
    /// <summary>
    /// Expands ~ to $HOME for use in bash commands.
    /// Works on both macOS bash and Linux bash.
    /// </summary>
    public static string Expand(string path) =>
        path.StartsWith("~/") ? "$HOME" + path[1..] : path;

    /// <summary>
    /// Expands ~ to the actual home directory path for use in C# file operations.
    /// </summary>
    public static string ExpandFull(string path) =>
        path.StartsWith("~/")
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), path[2..])
            : path;
}
