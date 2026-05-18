package bandit

import org.junit.jupiter.api.Test
import org.tomlj.Toml
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class BanditHelperTest {

    private fun findRepoRoot(): Path {
        var cwd = Paths.get("").toAbsolutePath()
        while (true) {
            if (Files.exists(cwd.resolve("levels").resolve("bandit-levels.toml"))) return cwd
            cwd = cwd.parent ?: error("repo root not found")
        }
    }

    @Test
    fun loadSharedConfig() {
        val root = findRepoRoot()
        val result = Toml.parse(root.resolve("levels").resolve("bandit-levels.toml"))
        assertTrue(!result.hasErrors(), "config parses without errors")

        assertEquals("bandit.labs.overthewire.org", result.getString("connection.host"))
        assertEquals(2220L, result.getLong("connection.port"))
        assertEquals(0L, result.getLong("bootstrap.level"))
        assertEquals("bandit0", result.getString("bootstrap.password"))

        val steps = result.getArray("steps")
        assertNotNull(steps)
        assertEquals(32, steps.size())

        val bandit26 = steps.getTable(25)
        assertEquals("bandit26_escape", bandit26.getString("type"))
        val targets = bandit26.getArray("to")
        assertNotNull(targets)
        assertEquals(2, targets.size())
        assertEquals(26L, targets.getLong(0))
        assertEquals(27L, targets.getLong(1))
    }

    @Test
    fun envOrFallsBack() {
        assertEquals("fallback", BanditHelper.envOr("BANDIT_DEFINITELY_UNSET_VARIABLE", "fallback"))
    }
}
