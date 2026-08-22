from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class AttestationWorkflowTests(unittest.TestCase):
    def test_release_workflows_use_the_current_attestation_action(self) -> None:
        for name in ("release-core.yml", "release-macos.yml"):
            workflow = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
            self.assertIn("artifact-metadata: write", workflow)
            self.assertIn("actions/attest@", workflow)
            self.assertNotIn("actions/attest-build-provenance@", workflow)
            self.assertNotIn("actions/attest-sbom@", workflow)


if __name__ == "__main__":
    unittest.main()
