using Tomlyn;
using Tomlyn.Model;
using Xunit;

namespace Bandit.Tests;

public class BanditHelperTests
{
    private static string FindRepoRoot()
    {
        var cwd = Directory.GetCurrentDirectory();
        while (true)
        {
            if (File.Exists(Path.Combine(cwd, "levels", "bandit-levels.toml"))) return cwd;
            var parent = Directory.GetParent(cwd)?.FullName
                ?? throw new InvalidOperationException("repo root not found");
            if (parent == cwd) throw new InvalidOperationException("repo root not found");
            cwd = parent;
        }
    }

    [Fact]
    public void LoadSharedConfigMatchesParityExpectations()
    {
        var root = FindRepoRoot();
        var text = File.ReadAllText(Path.Combine(root, "levels", "bandit-levels.toml"));
        Assert.True(Toml.TryToModel<TomlTable>(text, out var cfg, out _));

        var conn = (TomlTable)cfg!["connection"];
        Assert.Equal("bandit.labs.overthewire.org", conn["host"]);
        Assert.Equal(2220L, conn["port"]);

        var boot = (TomlTable)cfg["bootstrap"];
        Assert.Equal(0L, boot["level"]);
        Assert.Equal("bandit0", boot["password"]);

        var steps = (TomlTableArray)cfg["steps"];
        Assert.Equal(32, steps.Count);

        var bandit26 = steps[25];
        Assert.Equal("bandit26_escape", bandit26["type"]);
        var targets = (TomlArray)bandit26["to"];
        Assert.Equal(2, targets.Count);
        Assert.Equal(26L, targets[0]);
        Assert.Equal(27L, targets[1]);
    }

    [Fact]
    public void ExtractPasswordReturnsLastMatch()
    {
        var text = "noise abcdefghijklmnopqrstuvwxyz012345 then ABCDEFGHIJKLMNOPQRSTUVWXYZ012345 tail";
        Assert.Equal("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", BanditHelper.ExtractPassword(text));
        Assert.Equal(2, BanditHelper.ExtractPasswords(text).Count);
    }

    [Fact]
    public void StripTerminalCodesRemovesAnsiAndCarriageReturns()
    {
        var dirty = "hello[31mred[0m\rworld";
        Assert.Equal("helloredworld", BanditHelper.StripTerminalCodes(dirty));
    }

    [Fact]
    public void RenderTemplateReplacesAllPlaceholders()
    {
        var result = BanditHelper.RenderTemplate(
            "level={level} pass={password} {password}",
            new Dictionary<string, string> { ["level"] = "7", ["password"] = "abc" });
        Assert.Equal("level=7 pass=abc abc", result);
    }

    [Fact]
    public void EnvOrFallsBack()
    {
        Assert.Equal("fallback", BanditHelper.EnvOr("BANDIT_DEFINITELY_UNSET_VARIABLE", "fallback"));
    }
}
