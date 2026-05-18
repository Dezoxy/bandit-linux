package bandit;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class BanditHelperTest {

    @Test
    void loadSharedConfig() throws Exception {
        BanditHelper helper = new BanditHelper();
        helper.repoRoot = helper.findRepoRoot();
        helper.configPath = helper.repoRoot.resolve("levels").resolve("bandit-levels.toml");

        BanditHelper.Config cfg = helper.loadConfig();

        assertEquals(BanditHelper.DEFAULT_HOST, cfg.host);
        assertEquals(2220, cfg.port);
        assertEquals(0, cfg.bootstrapLevel);
        assertEquals("bandit0", cfg.bootstrapPassword);
        assertEquals(32, cfg.steps.size());

        BanditHelper.Step bandit26Step = cfg.steps.get(25);
        assertEquals("bandit26_escape", bandit26Step.type);
        List<Integer> targets = bandit26Step.mustToList();
        assertEquals(List.of(26, 27), targets);
    }

    @Test
    void extractsLastPassword() {
        String text = "noise abcdefghijklmnopqrstuvwxyz012345 then ABCDEFGHIJKLMNOPQRSTUVWXYZ012345AA tail";
        String password = BanditHelper.extractPassword(text);
        assertNotNull(password);
        assertEquals("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345AA".substring(0, 32), password);
    }

    @Test
    void stripsAnsiAndCarriageReturns() {
        String dirty = "hello[31mred[0m\rworld";
        assertEquals("helloredworld", BanditHelper.stripTerminalCodes(dirty));
    }

    @Test
    void findsRepoRootFromWorkingDir() {
        BanditHelper helper = new BanditHelper();
        Path root = helper.findRepoRoot();
        assertNotNull(root);
        assertEquals(true, java.nio.file.Files.exists(root.resolve("levels").resolve("bandit-levels.toml")));
    }
}
