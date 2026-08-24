from __future__ import annotations

import importlib.util
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPOSITORY_ROOT = HERE.parents[2]
RECEIPT_TOOL = REPOSITORY_ROOT / "scripts" / "current_cpa_audit_unit_receipt.py"
SPEC = importlib.util.spec_from_file_location(
    "current_cpa_audit_unit_receipt_under_test", RECEIPT_TOOL
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"could not load receipt tool: {RECEIPT_TOOL}")
receipt_tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(receipt_tool)


class UnitReceiptTimingTests(unittest.TestCase):
    def test_utc_millisecond_format_truncates_submillisecond_precision(self) -> None:
        value = datetime(
            2026,
            8,
            21,
            20,
            37,
            46,
            422_999,
            tzinfo=timezone.utc,
        )

        self.assertEqual(
            receipt_tool.format_utc_milliseconds(value),
            "2026-08-21T20:37:46.422Z",
        )

    def test_elapsed_timing_accepts_bounded_scheduler_delta(self) -> None:
        started = datetime(2026, 8, 21, 20, 37, 46, 422_000, tzinfo=timezone.utc)
        finished = started + timedelta(milliseconds=34_757)

        for elapsed_ms in (29_757, 34_756, 34_757, 34_758, 39_757):
            with self.subTest(elapsed_ms=elapsed_ms):
                receipt_tool.validate_elapsed_timing(started, finished, elapsed_ms)

    def test_elapsed_timing_rejects_delta_above_scheduler_bound(self) -> None:
        started = datetime(2026, 8, 21, 20, 37, 46, 422_000, tzinfo=timezone.utc)
        finished = started + timedelta(milliseconds=34_757)

        for elapsed_ms in (29_756, 39_758):
            with self.subTest(elapsed_ms=elapsed_ms), self.assertRaisesRegex(
                receipt_tool.ReceiptError,
                "maximum permitted difference is 5000 ms",
            ):
                receipt_tool.validate_elapsed_timing(started, finished, elapsed_ms)


if __name__ == "__main__":
    unittest.main()
