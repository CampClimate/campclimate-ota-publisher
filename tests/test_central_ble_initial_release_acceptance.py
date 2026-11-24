from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import release_acceptance
from release_acceptance import ReleaseAcceptanceError, validate_release_acceptance


UTC = dt.timezone.utc
NOW = dt.datetime.fromisoformat("2026-11-12T13:00:00+00:00")
APPROVED_AT = "2026-11-12T12:00:00+00:00"


class CentralBleInitialReleaseAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="central-ble-initial-acceptance-")
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.receipt_path = self.root / "acceptance.json"
        self.final_binding = {
            **release_acceptance._CENTRAL_BLE_INITIAL_CANDIDATE,
            "file_size": 321,
            "sha256": hashlib.sha256(b"final signed candidate").hexdigest(),
        }
        self.candidate = dict(self.final_binding)
        self.receipt = self._make_receipt(self.candidate)

    def _evidence(self, name: str, body: str) -> dict[str, str]:
        path = self.root / name
        path.write_text(body, encoding="utf-8")
        return {"evidence_file": name, "evidence_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    def _make_receipt(self, candidate: dict[str, object]) -> dict[str, object]:
        evidence = {
            "software": self._evidence("software.txt", "Software tests passed."),
            "test_firmware": self._evidence("test-firmware.txt", "Not performed: no hardware acceptance claimed."),
            "vehicle": self._evidence("vehicle.txt", "Not performed: no customer systems in field."),
            "authorization": self._evidence(
                "authorization.txt", release_acceptance._CENTRAL_BLE_INITIAL_EXCEPTION_REASON
            ),
        }
        raw: dict[str, object] = {
            "schema_version": 2,
            "candidate": dict(candidate),
            "stages": {
                "software": {
                    "status": "passed", "tested_by": "Codex (software checks)",
                    "completed_at": APPROVED_AT, **evidence["software"],
                },
                "test_firmware": {
                    "status": "open", "tested_by": "not tested",
                    "completed_at": None, **evidence["test_firmware"],
                },
                "vehicle": {
                    "status": "open", "tested_by": "not tested",
                    "completed_at": None, **evidence["vehicle"],
                },
            },
            "approval": {
                "status": "approved_by_exception", "approved_by": "Bastian Schnier",
                "approved_at": APPROVED_AT,
            },
            "exception": {
                "exception_id": release_acceptance._CENTRAL_BLE_INITIAL_EXCEPTION_ID,
                "reason": release_acceptance._CENTRAL_BLE_INITIAL_EXCEPTION_REASON,
                **evidence["authorization"],
            },
        }
        self.receipt_path.write_text(json.dumps(raw), encoding="utf-8")
        return raw

    def test_exact_candidate_accepts_only_after_signed_bin_identity_is_pinned(self) -> None:
        original = dict(release_acceptance._CENTRAL_BLE_INITIAL_CANDIDATE)
        with mock.patch.dict(release_acceptance._CENTRAL_BLE_INITIAL_CANDIDATE,
                             {"file_size": None, "sha256": None}):
            with self.assertRaisesRegex(ReleaseAcceptanceError, "noch nicht freigeschaltet"):
                validate_release_acceptance(self.candidate, self.receipt_path, now=NOW)

        with mock.patch.dict(release_acceptance._CENTRAL_BLE_INITIAL_CANDIDATE, self.final_binding):
            result = validate_release_acceptance(self.candidate, self.receipt_path, now=NOW)

        self.assertEqual(release_acceptance._CENTRAL_BLE_INITIAL_CANDIDATE, original)
        self.assertEqual(result["candidate"], self.final_binding)
        self.assertEqual(result["exception"]["exception_id"], release_acceptance._CENTRAL_BLE_INITIAL_EXCEPTION_ID)
        self.assertEqual(result["exception"]["reason"], release_acceptance._CENTRAL_BLE_INITIAL_EXCEPTION_REASON)
        self.assertEqual(result["stages"]["software"]["status"], "passed")
        self.assertEqual(result["stages"]["test_firmware"]["status"], "open")
        self.assertEqual(result["stages"]["vehicle"]["status"], "open")

    def test_exception_rejects_changed_candidate_identity(self) -> None:
        with mock.patch.dict(release_acceptance._CENTRAL_BLE_INITIAL_CANDIDATE, self.final_binding):
            for field, value in (
                ("target", "outdoor"), ("version", "2.2.0.7"),
                ("release_sequence", 21), ("file_size", self.candidate["file_size"] + 1),
                ("sha256", "0" * 64), ("mandatory", True),
            ):
                with self.subTest(field=field):
                    altered = dict(self.candidate)
                    altered[field] = value
                    receipt = self._make_receipt(altered)
                    self.receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
                    with self.assertRaises(ReleaseAcceptanceError):
                        validate_release_acceptance(altered, self.receipt_path, now=NOW)

    def test_exception_cannot_claim_hardware_passed_or_change_user_authorization(self) -> None:
        with mock.patch.dict(release_acceptance._CENTRAL_BLE_INITIAL_CANDIDATE, self.final_binding):
            for stage_name in ("test_firmware", "vehicle"):
                raw = self._make_receipt(self.candidate)
                stage = raw["stages"][stage_name]
                stage.update(status="passed", tested_by="Bastian Schnier", completed_at=APPROVED_AT)
                self.receipt_path.write_text(json.dumps(raw), encoding="utf-8")
                with self.subTest(stage=stage_name), self.assertRaises(ReleaseAcceptanceError):
                    validate_release_acceptance(self.candidate, self.receipt_path, now=NOW)

            raw = self._make_receipt(self.candidate)
            raw["exception"]["reason"] += " (changed)"
            self.receipt_path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaisesRegex(ReleaseAcceptanceError, "Ausnahmegrund stimmt nicht"):
                validate_release_acceptance(self.candidate, self.receipt_path, now=NOW)


if __name__ == "__main__":
    unittest.main()
