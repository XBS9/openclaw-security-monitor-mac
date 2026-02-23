using OpenClawSecurityMonitorMac.Core;

namespace OpenClawSecurityMonitorMac.Services;

public class AutoPatchService
{
    private readonly ICommandService _cmd;
    private readonly TraySettings _settings;

    public event Action<string>? Progress;

    public AutoPatchService(ICommandService cmd, TraySettings settings)
    {
        _cmd = cmd;
        _settings = settings;
    }

    public async Task<string> GetOpenClawVersionAsync()
    {
        var npmPath = PathUtils.Expand(_settings.NpmGlobalPath);
        var (_, output, _) = await _cmd.RunAsync(
            $"\"{npmPath}/bin/openclaw\" --version 2>/dev/null || echo unknown");
        return output.Trim();
    }

    public async Task<(bool Success, string Log)> RunPatchAsync()
    {
        var log = new System.Text.StringBuilder();
        var npmPath = PathUtils.Expand(_settings.NpmGlobalPath);
        var distPath = $"{npmPath}/lib/node_modules/openclaw/dist";

        void Log(string msg)
        {
            log.AppendLine(msg);
            Progress?.Invoke(msg);
        }

        try
        {
            Log("Scanning dist files for auth token comparison patterns...");

            var findCmd = $"grep -rl 'token ==\\|token ===' \"{distPath}\"/ 2>/dev/null " +
                          $"| grep -v '__safeTokenEqual' || true";
            var (_, unpatchedOutput, _) = await _cmd.RunAsync(findCmd);

            var unpatchedFiles = unpatchedOutput
                .Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Where(f => !string.IsNullOrWhiteSpace(f))
                .Where(f => !f.Any(c => c == '\'' || c == '"' || c == '$' || c == '`' || c == '\\' || c == ';' || c == '|' || c == '&'))
                .ToList();

            var (_, patchedOutput, _) = await _cmd.RunAsync(
                $"grep -rl '__safeTokenEqual' \"{distPath}\"/ 2>/dev/null || true");
            var patchedFiles = patchedOutput
                .Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Where(f => !string.IsNullOrWhiteSpace(f))
                .ToList();

            Log($"Found {patchedFiles.Count} already-patched files, {unpatchedFiles.Count} need patching.");

            if (unpatchedFiles.Count == 0 && patchedFiles.Count >= _settings.ExpectedPatchedFileCount)
            {
                Log("All patches are intact. No action needed.");
                return (true, log.ToString());
            }

            int patchedCount = 0;
            foreach (var file in unpatchedFiles)
            {
                Log($"Patching: {Path.GetFileName(file)}");

                // macOS sed uses -i '' for in-place editing (different from GNU sed)
                var patchCmd =
                    $"if ! grep -q '__safeTokenEqual' '{file}'; then " +
                    $"sed -i '' '1s/^/function __safeTokenEqual(a,b){{if(typeof a!==\"string\"||typeof b!==\"string\")return false;if(a.length!==b.length)return false;let r=0;for(let i=0;i<a.length;i++)r|=a.charCodeAt(i)^b.charCodeAt(i);return r===0;}}\\n/' '{file}' && " +
                    $"sed -E -i '' 's/\\btoken[[:space:]]*===[[:space:]]*([^);&|,]+)/__safeTokenEqual(token, \\1)/g; s/\\btoken[[:space:]]*==[[:space:]]*([^);&|,=]+)/__safeTokenEqual(token, \\1)/g' '{file}'; " +
                    "fi";

                var (exitCode, _, error) = await _cmd.RunAsync(patchCmd);
                if (exitCode == 0)
                {
                    patchedCount++;
                    Log($"  Patched successfully.");
                }
                else
                {
                    Log($"  FAILED: {error}");
                }
            }

            Log($"\nPatch complete: {patchedCount}/{unpatchedFiles.Count} files patched.");
            Log($"Total patched files: {patchedFiles.Count + patchedCount}");

            var (_, verifyOutput, _) = await _cmd.RunAsync(
                $"grep -rl '__safeTokenEqual' \"{distPath}\"/ 2>/dev/null | wc -l || echo 0");
            Log($"Verification: {verifyOutput.Trim()} files contain __safeTokenEqual");

            return (true, log.ToString());
        }
        catch (Exception ex)
        {
            Log($"Error during patching: {ex.Message}");
            return (false, log.ToString());
        }
    }
}
