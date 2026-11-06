from __future__ import annotations

import contextlib
import io
import json
import unittest
from pathlib import Path

from bench import bench

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
TARGET = "10.77.0.2"
EXPECTED = {
    bench.Target(TARGET, 80),
    bench.Target(TARGET, 443),
    bench.Target(TARGET, 3306),
    bench.Target(TARGET, 8080),
}
LAB_TRUTH = EXPECTED | {bench.Target(TARGET, 8081)}


class ParserTests(unittest.TestCase):
    def test_nmap(self) -> None:
        output = (FIXTURES / "nmap.xml").read_text(encoding="utf-8")
        self.assertEqual(bench.parse_nmap(output, TARGET), EXPECTED)

    def test_masscan(self) -> None:
        output = (FIXTURES / "masscan.json").read_text(encoding="utf-8")
        self.assertEqual(bench.parse_masscan(output, TARGET), EXPECTED)

    def test_rustscan(self) -> None:
        output = (FIXTURES / "rustscan.txt").read_text(encoding="utf-8")
        self.assertEqual(bench.parse_rustscan(output, TARGET), EXPECTED)

    def test_rayscan(self) -> None:
        output = (FIXTURES / "rayscan.json").read_text(encoding="utf-8")
        self.assertEqual(bench.parse_rayscan(output, TARGET), EXPECTED)

    def test_rayscan_accepts_plain_port_list(self) -> None:
        output = json.dumps({"open": [80, 443]})
        self.assertEqual(
            bench.parse_rayscan(output, TARGET),
            {bench.Target(TARGET, 80), bench.Target(TARGET, 443)},
        )

    def test_rayscan_accepts_json_lines(self) -> None:
        output = "\n".join(
            [
                json.dumps({"host": TARGET, "port": 80, "state": "open"}),
                json.dumps({"host": TARGET, "port": 81, "state": "closed"}),
            ]
        )
        self.assertEqual(bench.parse_rayscan(output, TARGET), {bench.Target(TARGET, 80)})

    def test_empty_output_is_empty(self) -> None:
        self.assertEqual(bench.parse_nmap("<nmaprun/>", TARGET), set())
        self.assertEqual(bench.parse_masscan("", TARGET), set())
        self.assertEqual(bench.parse_rustscan("", TARGET), set())
        self.assertEqual(bench.parse_rayscan("", TARGET), set())


class MetricTests(unittest.TestCase):
    def test_perfect_score(self) -> None:
        metrics = bench.score(EXPECTED, EXPECTED)
        self.assertEqual(metrics.true_positives, 4)
        self.assertEqual(metrics.false_positives, 0)
        self.assertEqual(metrics.false_negatives, 0)
        self.assertEqual(metrics.recall, 1.0)
        self.assertEqual(metrics.precision, 1.0)
        self.assertEqual(metrics.f1, 1.0)

    def test_false_positive_and_negative(self) -> None:
        predicted = {bench.Target(TARGET, 80), bench.Target(TARGET, 81)}
        truth = {bench.Target(TARGET, 80), bench.Target(TARGET, 443)}
        metrics = bench.score(predicted, truth)
        self.assertEqual(metrics.true_positives, 1)
        self.assertEqual(metrics.false_positives, 1)
        self.assertEqual(metrics.false_negatives, 1)
        self.assertEqual(metrics.recall, 0.5)
        self.assertEqual(metrics.precision, 0.5)


class CommandTests(unittest.TestCase):
    def test_rayscan_command_matches_contract(self) -> None:
        command = bench.build_command(
            "rayscan", TARGET, "80,443", 1000, 30, Path("/tmp/rayscan")
        )
        self.assertEqual(command[0], "/tmp/rayscan")
        self.assertIn("scan", command)
        self.assertIn("--json", command)

    def test_masscan_has_rate_and_json(self) -> None:
        command = bench.build_command("masscan", TARGET, "80,443", 5000, 30, Path("x"))
        self.assertIn("--rate", command)
        self.assertIn("5000", command)
        self.assertIn("-oJ", command)

    def test_lab_truth(self) -> None:
        target, ports, truth = bench.load_lab(bench.DEFAULT_TRUTH)
        self.assertEqual(target, TARGET)
        self.assertIn("9001", ports)
        self.assertIn("9003", ports)
        self.assertEqual(truth, LAB_TRUTH)

    def test_dry_run_succeeds_without_tools(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = bench.main(
                ["--lab", "--dry-run", "--tools", "rayscan", "--no-save"]
            )
        self.assertEqual(code, 0)
        self.assertIn("scan", output.getvalue())


if __name__ == "__main__":
    unittest.main()
