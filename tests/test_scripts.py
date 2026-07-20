import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


class ShellWorkflowScriptsTest(unittest.TestCase):
    def test_linux_shell_scripts_exist_and_use_strict_mode(self):
        for script_name in ("run_demo.sh", "run_evaluation.sh"):
            content = (SCRIPTS / script_name).read_text(encoding="utf-8")
            self.assertTrue(content.startswith("#!/usr/bin/env bash\n"), script_name)
            self.assertIn("set -euo pipefail", content)
            self.assertIn("repo_root=", content)
            self.assertIn("cert_root=", content)

    def test_linux_shell_scripts_mirror_core_powershell_workflows(self):
        demo = (SCRIPTS / "run_demo.sh").read_text(encoding="utf-8")
        evaluation = (SCRIPTS / "run_evaluation.sh").read_text(encoding="utf-8")

        for content in (demo, evaluation):
            self.assertIn("docker compose up -d", content)
            self.assertIn("1_prepare_cert_data.py", content)
            self.assertIn("2_stream_cert.py", content)
            self.assertIn("evaluation.py", content)
            self.assertIn("artifacts/evaluation_stream.jsonl", content)
            self.assertIn("artifacts/graph_metrics.json", content)
            self.assertIn("artifacts/rule_metrics.json", content)
            self.assertIn("artifacts/comparison.json", content)

        self.assertIn("--limit", demo)
        self.assertIn("artifacts/run_profile.json", evaluation)
        self.assertIn("--skip-prepare", evaluation)
        self.assertIn("--skip-replay", evaluation)
        self.assertIn("--no-docker", evaluation)

    def test_linux_shell_scripts_parse_with_bash(self):
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("bash is not available")
        for script_name in ("run_demo.sh", "run_evaluation.sh"):
            result = subprocess.run(
                [bash, "-n", str(SCRIPTS / script_name)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
