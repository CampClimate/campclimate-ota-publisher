from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import release_acceptance
from release_acceptance import ReleaseAcceptanceError, validate_release_acceptance


UTC = dt.timezone.utc
APPROVED_AT = "2026-10-24T08:17:09+00:00"


class OutdoorInitialReleaseAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="outdoor-initial-acceptance-")
        self.root = Path(self.temp_dir.name)
        self.receipt_path = self.root / "acceptance.json"
        self.candidate = dict(release_acceptance._OUTDOOR_INITIAL_CANDIDATE)
        self._write_receipt()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _evidence(self, name: str, content: str) -> dict[str, str]:
        path = self.root / name
        path.write_text(content, encoding="utf-8")
        return {"evidence_file": path.name, "evidence_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    def _write_receipt(self, *, candidate: dict[str, object] | None = None) -> dict[str, object]:
        software = self._evidence(
            "software-evidence.txt", "Software checks: recorded logs and focused acceptance tests passed."
        )
        test_firmware = self._evidence(
            "test-firmware-evidence.txt", "Not performed: explicitly waived for this initial release."
        )
        vehicle = self._evidence(
            "vehicle-evidence.txt", "Not performed: explicitly open for this initial release."
        )
        exception = self._evidence(
            "user-authorization.txt", release_acceptance._OUTDOOR_INITIAL_EXCEPTION_REASON
        )
        raw: dict[str, object] = {
            "schema_version": 2,
            "candidate": dict(candidate if candidate is not None else self.candidate),
            "stages": {
                "software": {
                    "status": "passed", "tested_by": "Codex (software checks)",
                    "completed_at": APPROVED_AT, **software,
                },
                "test_firmware": {
                    "status": "waived", "tested_by": "not tested",
                    "completed_at": None, **test_firmware,
                },
                "vehicle": {
                    "status": "open", "tested_by": "not tested",
                    "completed_at": None, **vehicle,
                },
            },
            "approval": {
                "status": "approved_by_exception", "approved_by": "Bastian Schnier",
                "approved_at": APPROVED_AT,
            },
            "exception": {
                "exception_id": release_acceptance._OUTDOOR_INITIAL_EXCEPTION_ID,
                "reason": release_acceptance._OUTDOOR_INITIAL_EXCEPTION_REASON,
                **exception,
            },
        }
        self.receipt_path.write_text(json.dumps(raw), encoding="utf-8")
        return raw

    def test_exact_outdoor_initial_candidate_accepts_with_hardware_open(self) -> None:
        snapshot = validate_release_acceptance(
            self.candidate, self.receipt_path,
            now=dt.datetime.fromisoformat("2026-10-24T08:20:00+00:00"),
        )
        self.assertEqual(snapshot["candidate"], self.candidate)
        self.assertEqual(snapshot["stages"]["software"]["status"], "passed")
        self.assertEqual(snapshot["stages"]["test_firmware"]["status"], "waived")
        self.assertEqual(snapshot["stages"]["vehicle"]["status"], "open")
        self.assertEqual(snapshot["exception"]["exception_id"], release_acceptance._OUTDOOR_INITIAL_EXCEPTION_ID)

    def test_exception_rejects_any_other_candidate_identity(self) -> None:
        for field, value in (
            ("target", "central"), ("version", "1.0.0.1"),
            ("release_sequence", 2), ("file_size", self.candidate["file_size"] + 1),
            ("sha256", "0" * 64), ("mandatory", True),
        ):
            with self.subTest(field=field):
                altered = dict(self.candidate)
                altered[field] = value
                self._write_receipt(candidate=altered)
                with self.assertRaises(ReleaseAcceptanceError):
                    validate_release_acceptance(
                        altered, self.receipt_path,
                        now=dt.datetime.fromisoformat("2026-10-24T08:20:00+00:00"),
                    )

    def test_exception_rejects_foreign_authorization_and_passed_hardware(self) -> None:
        for exception_id, reason in (
            (release_acceptance._CENTRAL_INITIAL_EXCEPTION_ID,
             release_acceptance._CENTRAL_INITIAL_EXCEPTION_REASON),
            (release_acceptance._BASIC_EXCEPTION_ID,
             release_acceptance._BASIC_EXCEPTION_REASON),
        ):
            with self.subTest(exception_id=exception_id):
                raw = self._write_receipt()
                raw["exception"]["exception_id"] = exception_id
                raw["exception"]["reason"] = reason
                self.receipt_path.write_text(json.dumps(raw), encoding="utf-8")
                with self.assertRaises(ReleaseAcceptanceError):
                    validate_release_acceptance(
                        self.candidate, self.receipt_path,
                        now=dt.datetime.fromisoformat("2026-10-24T08:20:00+00:00"),
                    )

        for name in ("test_firmware", "vehicle"):
            with self.subTest(stage=name):
                raw = self._write_receipt()
                raw["stages"][name]["status"] = "passed"
                raw["stages"][name]["tested_by"] = "Bastian Schnier"
                raw["stages"][name]["completed_at"] = APPROVED_AT
                self.receipt_path.write_text(json.dumps(raw), encoding="utf-8")
                with self.assertRaises(ReleaseAcceptanceError):
                    validate_release_acceptance(
                        self.candidate, self.receipt_path,
                        now=dt.datetime.fromisoformat("2026-10-24T08:20:00+00:00"),
                    )


if __name__ == "__main__":
    unittest.main()
