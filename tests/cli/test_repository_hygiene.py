from pathlib import Path
import subprocess
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class RepositoryHygieneTests(unittest.TestCase):
    def test_local_agent_handoff_files_remain_ignored(self) -> None:
        entries = {
            line.strip()
            for line in (REPOSITORY_ROOT / ".gitignore").read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }

        required_local_entries = {
            "AGENTS.md",
            "CLAUDE.md",
            "letsinfer.md",
            "context/",
            "scratchpad/",
        }
        self.assertTrue(required_local_entries.issubset(entries))

    def test_local_instruction_alias_remains_relative_symlink(self) -> None:
        agents = REPOSITORY_ROOT / "AGENTS.md"
        claude = REPOSITORY_ROOT / "CLAUDE.md"
        if not agents.exists():
            self.assertFalse(claude.exists())
            return

        self.assertTrue(claude.is_symlink())
        self.assertEqual(claude.readlink(), Path("AGENTS.md"))

    def test_local_agent_handoff_files_are_ignored_and_untracked(self) -> None:
        if not (REPOSITORY_ROOT / ".git").exists():
            self.skipTest("Git metadata is not present in the source archive")

        local_paths = (
            "AGENTS.md",
            "CLAUDE.md",
            "letsinfer.md",
            "context/README.md",
            "scratchpad/coordinator-impl/plan.md",
        )
        ignored = subprocess.run(
            ("git", "check-ignore", "--", *local_paths),
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            set(ignored.stdout.splitlines()),
            set(local_paths),
            "every local handoff path must be ignored",
        )

        tracked = subprocess.run(
            (
                "git",
                "ls-files",
                "--",
                "AGENTS.md",
                "CLAUDE.md",
                "letsinfer.md",
                "context",
                "scratchpad",
            ),
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(tracked.stdout, "", "local handoff files must stay untracked")

    def test_public_markdown_does_not_reference_local_only_material(self) -> None:
        roots = (
            REPOSITORY_ROOT / "README.md",
            REPOSITORY_ROOT / "documentation",
            REPOSITORY_ROOT / "benchmarks",
            REPOSITORY_ROOT / "adapters",
            REPOSITORY_ROOT / "connectors",
            REPOSITORY_ROOT / "skills",
            REPOSITORY_ROOT / "apps/macos",
        )
        forbidden = ("AGENTS.md", "CLAUDE.md", "letsinfer.md", "context/", "scratchpad/")
        files = []
        for root in roots:
            files.extend([root] if root.is_file() else root.rglob("*.md"))
        for path in sorted(files):
            value = path.read_text(encoding="utf-8")
            for token in forbidden:
                self.assertNotIn(token, value, f"{path} references local-only {token}")

    def test_runtime_skills_route_engine_work_and_use_the_simple_quorum(self) -> None:
        skill_root = REPOSITORY_ROOT / "skills"
        expected = {
            "benchmark",
            "cli",
            "engine-authoring",
            "runtime",
            "runtime-review",
        }
        values = {}
        for name in expected:
            path = skill_root / name / "SKILL.md"
            self.assertTrue(path.is_file(), f"missing public skill: {name}")
            values[name] = path.read_text(encoding="utf-8")
            self.assertIn(f"name: {name}\n", values[name])

        combined = "\n".join(values.values()).lower()
        for obsolete in (
            "three agreeing",
            "three independent",
            "five independent",
            "coefficient of variation",
            "expanded quorum",
        ):
            self.assertNotIn(obsolete, combined)

        self.assertIn("../engine-authoring/SKILL.md", values["runtime"])
        self.assertIn("../runtime-review/SKILL.md", values["runtime"])
        self.assertIn("two successful independent", values["benchmark"].lower())
        review_words = " ".join(values["runtime-review"].lower().split())
        self.assertIn("one reviewer always occupies one slot", review_words)
        self.assertIn("https://letsinfer.ai/install.sh", values["runtime"])
        self.assertNotIn("docker login", combined)


if __name__ == "__main__":
    unittest.main()
