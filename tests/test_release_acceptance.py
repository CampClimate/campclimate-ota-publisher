from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import publisher
import release_acceptance
from release_acceptance import ReleaseAcceptanceError, validate_release_acceptance


UTC = dt.timezone.utc


class ReleaseAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="campclimate-acceptance-")
        self.root = Path(self.temp_dir.name)
        self.env_file_patch = mock.patch.object(
            publisher, "ENV_FILE", self.root / "env-does-not-exist"
        )
        self.env_file_patch.start()
        self.addCleanup(self.env_file_patch.stop)
        self.times = [
            "2020-01-01T08:00:00+00:00",
            "2020-01-01T08:01:00+00:00",
            "2020-01-01T08:02:00+00:00",
        ]
        self.summary = {
            "target": "basic",
            "version": "2.0.1.99",
            "release_sequence": 99,
            "file_size": 8,
            "sha256": hashlib.sha256(b"firmware").hexdigest(),
            "mandatory": False,
        }
        self.receipt = self.root / "acceptance.json"
        self._write_receipt()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _write_receipt(self, **changes: object) -> None:
        stages: dict[str, dict[str, object]] = {}
        for name, timestamp, content in (
            ("software", self.times[0], b"software evidence"),
            ("test_firmware", self.times[1], b"test firmware evidence"),
            ("vehicle", self.times[2], b"vehicle evidence"),
        ):
            evidence = self.root / f"{name}.txt"
            evidence.write_bytes(content)
            stages[name] = {
                "status": "passed",
                "tested_by": "Human Testerin",
                "completed_at": timestamp,
                "evidence_file": evidence.name,
                "evidence_sha256": hashlib.sha256(content).hexdigest(),
            }
        value: dict[str, object] = {
            "schema_version": 1,
            "candidate": {
                "target": self.summary["target"],
                "version": self.summary["version"],
                "release_sequence": self.summary["release_sequence"],
                "file_size": self.summary["file_size"],
                "sha256": self.summary["sha256"],
                "mandatory": self.summary["mandatory"],
            },
            "stages": stages,
            "approval": {
                "status": "approved",
                "approved_by": "Release Owner",
                "approved_at": "2020-01-01T08:03:00+00:00",
            },
        }
        for key, replacement in changes.items():
            if key == "stages":
                value["stages"] = replacement
            else:
                value[key] = replacement
        self.receipt.write_text(
            json.dumps(value, separators=(",", ":")), encoding="utf-8"
        )

    def test_valid_receipt_returns_snapshot(self) -> None:
        snapshot = validate_release_acceptance(
            self.summary,
            self.receipt,
            now=dt.datetime(2020, 1, 1, 8, 4, tzinfo=UTC),
        )
        self.assertEqual(snapshot["candidate"], self.summary)
        self.assertEqual(snapshot["stages"]["vehicle"]["evidence_sha256"], hashlib.sha256(b"vehicle evidence").hexdigest())

    def test_pending_status_and_bad_hash_are_rejected(self) -> None:
        raw = json.loads(self.receipt.read_text(encoding="utf-8"))
        raw["stages"]["software"]["status"] = "pending"
        self.receipt.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaises(ReleaseAcceptanceError):
            validate_release_acceptance(self.summary, self.receipt)

        raw["stages"]["software"]["status"] = "passed"
        raw["stages"]["software"]["evidence_sha256"] = "0" * 64
        self.receipt.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaises(ReleaseAcceptanceError):
            validate_release_acceptance(self.summary, self.receipt)

    def test_order_timezone_types_duplicates_and_unknown_fields_are_rejected(self) -> None:
        raw = json.loads(self.receipt.read_text(encoding="utf-8"))
        raw["stages"]["vehicle"]["completed_at"] = self.times[1]
        self.receipt.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaises(ReleaseAcceptanceError):
            validate_release_acceptance(self.summary, self.receipt)

        self._write_receipt()
        raw = json.loads(self.receipt.read_text(encoding="utf-8"))
        raw["approval"]["approved_at"] = "2020-01-01T08:03:00"
        raw["extra"] = True
        self.receipt.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaises(ReleaseAcceptanceError):
            validate_release_acceptance(self.summary, self.receipt)

        self.receipt.write_text(
            '{"schema_version":1,"schema_version":1,"candidate":{},"stages":{},"approval":{}}',
            encoding="utf-8",
        )
        with self.assertRaises(ReleaseAcceptanceError):
            validate_release_acceptance(self.summary, self.receipt)

    def test_receipt_evidence_change_changes_snapshot_or_fails(self) -> None:
        first = validate_release_acceptance(
            self.summary,
            self.receipt,
            now=dt.datetime(2020, 1, 1, 8, 4, tzinfo=UTC),
        )
        (self.root / "vehicle.txt").write_bytes(b"changed evidence")
        with self.assertRaises(ReleaseAcceptanceError):
            validate_release_acceptance(
                self.summary,
                self.receipt,
                now=dt.datetime(2020, 1, 1, 8, 4, tzinfo=UTC),
            )
        self.assertTrue(first["receipt_sha256"])

    def test_publish_blocks_before_upload_when_acceptance_missing(self) -> None:
        firmware = self.root / "firmware.bin"
        firmware.write_bytes(b"firmware")
        env = {
            "SUPABASE_URL": "https://example.supabase.co",
            "SUPABASE_SERVICE_ROLE_KEY": "test-service-role",
            "SUPABASE_STORAGE_BUCKET": "firmware",
            "OTA_SIGNING_MODE": "disabled",
            "OTA_RELEASE_ACCEPTANCE_FILE": str(self.root / "missing.json"),
        }
        with mock.patch.dict("os.environ", env, clear=False):
            summary = publisher.prepare_release(
                firmware, "basic", "2.0.1.99", "test", False, 99
            )
            with mock.patch("publisher.upload_immutable_artifact") as upload:
                with self.assertRaises(RuntimeError):
                    publisher.publish_prepared_release(summary)
                upload.assert_not_called()

    def test_publish_rejects_receipt_change_before_patch(self) -> None:
        firmware = self.root / "firmware.bin"
        firmware.write_bytes(b"firmware")
        env = {
            "SUPABASE_URL": "https://example.supabase.co",
            "SUPABASE_SERVICE_ROLE_KEY": "test-service-role",
            "SUPABASE_STORAGE_BUCKET": "firmware",
            "OTA_SIGNING_MODE": "disabled",
            "OTA_RELEASE_ACCEPTANCE_FILE": str(self.receipt),
        }
        release = {
            "id": "release-id",
            "target": "basic",
            "version": "2.0.1.99",
            "notes": "test",
            "storage_path": "firmware/basic/sha256/" + self.summary["sha256"] + ".bin",
            "file_size_bytes": 8,
            "sha256": self.summary["sha256"],
            "mandatory": False,
            "published": False,
        }
        with mock.patch.dict("os.environ", env, clear=False):
            summary = publisher.prepare_release(firmware, "basic", "2.0.1.99", "test", False, 99)
            with mock.patch("publisher.preflight_release", return_value=None), mock.patch(
                "publisher.upload_immutable_artifact"
            ), mock.patch("publisher.insert_unpublished_release", return_value=release), mock.patch(
                "publisher.fetch_release_by_id", return_value=release
            ), mock.patch("publisher.mark_release_published") as publish:
                def mutate(*_args: object) -> None:
                    (self.root / "vehicle.txt").write_bytes(b"changed evidence")

                def mutate_and_return(*_args: object) -> dict[str, object]:
                    mutate()
                    return release

                with mock.patch("publisher.fetch_release_by_id", side_effect=mutate_and_return):
                    with self.assertRaises(RuntimeError):
                        publisher.publish_prepared_release(summary)
                publish.assert_not_called()

    def test_valid_stages_allow_existing_publish_flow(self) -> None:
        firmware = self.root / "firmware.bin"
        firmware.write_bytes(b"firmware")
        env = {
            "SUPABASE_URL": "https://example.supabase.co",
            "SUPABASE_SERVICE_ROLE_KEY": "test-service-role",
            "SUPABASE_STORAGE_BUCKET": "firmware",
            "OTA_SIGNING_MODE": "disabled",
            "OTA_RELEASE_ACCEPTANCE_FILE": str(self.receipt),
        }
        with mock.patch.dict("os.environ", env, clear=False):
            summary = publisher.prepare_release(firmware, "basic", "2.0.1.99", "test", False, 99)
        release = {
            "id": "release-id",
            "target": "basic",
            "version": "2.0.1.99",
            "notes": "test",
            "storage_path": "firmware/basic/sha256/" + self.summary["sha256"] + ".bin",
            "file_size_bytes": 8,
            "sha256": self.summary["sha256"],
            "mandatory": False,
            "published": False,
        }
        archived = self.root / "archive" / "firmware.bin"
        with mock.patch.dict("os.environ", env, clear=False), mock.patch(
            "publisher.preflight_release", return_value=None
        ), mock.patch("publisher.upload_immutable_artifact"), mock.patch(
            "publisher.insert_unpublished_release", return_value=release
        ), mock.patch("publisher.fetch_release_by_id", return_value=release), mock.patch(
            "publisher.mark_release_published",
            return_value={**release, "published": True},
        ) as publish, mock.patch(
            "publisher.archive_uploaded_file", return_value=archived
        ), mock.patch(
            "publisher.archive_release_record", return_value=self.root / "record.json"
        ):
            result = publisher.publish_prepared_release(summary)
        publish.assert_called_once()
        self.assertTrue(result["release"]["published"])
        self.assertIn("release_acceptance", summary)

    def test_direct_mark_rejects_unrelated_release_before_patch(self) -> None:
        summary = dict(self.summary)
        summary.update(
            {
                "notes": "test",
                "storage_path": "firmware/basic/sha256/" + self.summary["sha256"] + ".bin",
            }
        )
        unrelated = {
            "id": "requested-id",
            "target": "outdoor",
            "version": "2.0.1.99",
            "notes": "test",
            "storage_path": summary["storage_path"],
            "file_size_bytes": 8,
            "sha256": summary["sha256"],
            "mandatory": False,
            "published": False,
        }
        with mock.patch("publisher._validate_release_acceptance"), mock.patch(
            "publisher.fetch_release_by_id", return_value=unrelated
        ), mock.patch("publisher.request_json") as request:
            with self.assertRaises(RuntimeError):
                publisher.mark_release_published(
                    "https://example.supabase.co", "service-role", "requested-id", summary
                )
            request.assert_not_called()

    def test_direct_mark_rechecks_receipt_and_artifact_after_readback(self) -> None:
        firmware = self.root / "firmware.bin"
        firmware.write_bytes(b"firmware")
        summary = {
            **self.summary,
            "file_path": firmware,
            "file_size": 8,
            "notes": "test",
            "storage_path": "firmware/basic/sha256/" + self.summary["sha256"] + ".bin",
        }
        release = {
            "id": "release-id",
            "target": "basic",
            "version": "2.0.1.99",
            "notes": "test",
            "storage_path": summary["storage_path"],
            "file_size_bytes": 8,
            "sha256": summary["sha256"],
            "mandatory": False,
            "published": False,
        }
        env = {"OTA_RELEASE_ACCEPTANCE_FILE": str(self.receipt)}
        with mock.patch.dict("os.environ", env, clear=False):
            def mutate_and_return(*_args: object) -> dict[str, object]:
                (self.root / "vehicle.txt").write_bytes(b"changed evidence")
                return release

            with mock.patch("publisher.fetch_release_by_id", side_effect=mutate_and_return), mock.patch(
                "publisher.request_json"
            ) as request:
                with self.assertRaises(RuntimeError):
                    publisher.mark_release_published(
                        "https://example.supabase.co", "service-role", "release-id", summary
                    )
                request.assert_not_called()

    def test_schema2_exception_is_denied_until_exact_signed_identity_is_bound(self) -> None:
        summary = {
            "target": "central",
            "version": "2.2.0.4",
            "release_sequence": 5,
            "file_size": 2134016,
            "sha256": "050001e689e36e4028048f29d27da7c2bf1cf0740efd8bf2eb0cdca21609579a",
            "mandatory": False,
        }
        evidence = self.root / "exception.txt"
        evidence.write_text("User instruction and local evidence.", encoding="utf-8")
        evidence_hash = hashlib.sha256(evidence.read_bytes()).hexdigest()
        stages = {}
        for name, timestamp, content, status in (
            ("software", self.times[0], b"software evidence", "passed"),
            ("test_firmware", None, b"not performed: exception", "waived"),
            ("vehicle", None, b"not performed: exception", "open"),
        ):
            path = self.root / f"exception-{name}.txt"
            path.write_bytes(content)
            stages[name] = {"status": status, "tested_by": "Bastian Schnier" if timestamp else "not tested", "completed_at": timestamp, "evidence_file": path.name, "evidence_sha256": hashlib.sha256(content).hexdigest()}
        receipt = {"schema_version": 2, "candidate": summary, "stages": stages, "approval": {"status": "approved_by_exception", "approved_by": "Bastian Schnier", "approved_at": "2020-01-01T07:59:00+00:00"}, "exception": {"exception_id": "2026-10-20-central-2.2.0.4-seq5", "reason": "Dann mach mal die aktuelle Central Version fertig für die Cloud und lade Sie hoch\nDar freigegeben werden in diesem Fall", "evidence_file": evidence.name, "evidence_sha256": evidence_hash}}
        self.receipt.write_text(json.dumps(receipt), encoding="utf-8")
        old_binding = dict(release_acceptance._EXCEPTION_CANDIDATE)
        release_acceptance._EXCEPTION_CANDIDATE.update({"file_size": None, "sha256": None})
        with self.assertRaises(ReleaseAcceptanceError):
            validate_release_acceptance(summary, self.receipt, now=dt.datetime(2020, 1, 1, 8, 4, tzinfo=UTC))

        release_acceptance._EXCEPTION_CANDIDATE.update(old_binding)
        self.addCleanup(release_acceptance._EXCEPTION_CANDIDATE.update, old_binding)
        snapshot = validate_release_acceptance(summary, self.receipt, now=dt.datetime(2020, 1, 1, 8, 4, tzinfo=UTC))
        self.assertEqual(snapshot["schema_version"], 2)
        self.assertEqual(snapshot["stages"]["vehicle"]["status"], "open")
        self.assertEqual(snapshot["exception"]["evidence_sha256"], evidence_hash)
        raw = json.loads(self.receipt.read_text(encoding="utf-8"))
        for name in ("test_firmware", "vehicle"):
            raw["stages"][name]["status"] = "passed"
            self.receipt.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaises(ReleaseAcceptanceError):
                validate_release_acceptance(summary, self.receipt, now=dt.datetime(2020, 1, 1, 8, 4, tzinfo=UTC))
            raw["stages"][name]["status"] = "waived"
        self.receipt.write_text(json.dumps(receipt), encoding="utf-8")

    def test_schema2_rejects_changed_candidate_and_passed_hardware(self) -> None:
        self.test_schema2_exception_is_denied_until_exact_signed_identity_is_bound()
        raw = json.loads(self.receipt.read_text(encoding="utf-8"))
        summary = {
            "target": "central", "version": "2.2.0.4", "release_sequence": 5,
            "file_size": 2134016,
            "sha256": "050001e689e36e4028048f29d27da7c2bf1cf0740efd8bf2eb0cdca21609579a",
            "mandatory": False,
        }
        for field, value in (("target", "outdoor"), ("version", "2.2.0.5"), ("release_sequence", 6), ("file_size", 2134017), ("sha256", "0" * 64), ("mandatory", True)):
            candidate = dict(raw["candidate"])
            candidate[field] = value
            mutated = dict(raw)
            mutated["candidate"] = candidate
            mutated_summary = dict(summary)
            mutated_summary[field] = value
            self.receipt.write_text(json.dumps(mutated), encoding="utf-8")
            with self.assertRaises(ReleaseAcceptanceError):
                validate_release_acceptance(mutated_summary, self.receipt, now=dt.datetime(2020, 1, 1, 8, 4, tzinfo=UTC))

    def test_central_initial_exception_fails_closed_then_accepts_only_final_binding(self) -> None:
        summary = {
            "target": "central",
            "version": "2.2.0.5",
            "release_sequence": 7,
            "file_size": 2154496,
            "sha256": "c4c08f485759a201a27c912150c009444dd95cfaff335f089b5de81ab9d4c1f0",
            "mandatory": False,
        }
        evidence = self.root / "central-initial-authorization.txt"
        evidence.write_text(release_acceptance._CENTRAL_INITIAL_EXCEPTION_REASON, encoding="utf-8")
        evidence_hash = hashlib.sha256(evidence.read_bytes()).hexdigest()
        stages = {}
        for name, timestamp, content, status in (
            ("software", self.times[0], b"software tests passed", "passed"),
            ("test_firmware", None, b"not performed: initial release exception", "waived"),
            ("vehicle", None, b"not performed: no systems in field", "open"),
        ):
            path = self.root / f"central-initial-{name}.txt"
            path.write_bytes(content)
            stages[name] = {
                "status": status,
                "tested_by": "Bastian Schnier" if timestamp else "not tested",
                "completed_at": timestamp,
                "evidence_file": path.name,
                "evidence_sha256": hashlib.sha256(content).hexdigest(),
            }
        receipt = {
            "schema_version": 2,
            "candidate": summary,
            "stages": stages,
            "approval": {
                "status": "approved_by_exception",
                "approved_by": "Bastian Schnier",
                "approved_at": "2020-01-01T08:03:00+00:00",
            },
            "exception": {
                "exception_id": release_acceptance._CENTRAL_INITIAL_EXCEPTION_ID,
                "reason": release_acceptance._CENTRAL_INITIAL_EXCEPTION_REASON,
                "evidence_file": evidence.name,
                "evidence_sha256": evidence_hash,
            },
        }
        self.receipt.write_text(json.dumps(receipt), encoding="utf-8")

        old_binding = dict(release_acceptance._CENTRAL_INITIAL_CANDIDATE)
        final_binding = dict(release_acceptance._CENTRAL_INITIAL_CANDIDATE)
        release_acceptance._CENTRAL_INITIAL_CANDIDATE.update({"file_size": None, "sha256": None})
        with self.assertRaisesRegex(ReleaseAcceptanceError, "noch nicht freigeschaltet"):
            validate_release_acceptance(
                summary, self.receipt, now=dt.datetime(2020, 1, 1, 8, 4, tzinfo=UTC)
            )

        release_acceptance._CENTRAL_INITIAL_CANDIDATE.update(final_binding)
        self.addCleanup(release_acceptance._CENTRAL_INITIAL_CANDIDATE.update, old_binding)
        snapshot = validate_release_acceptance(
            summary, self.receipt, now=dt.datetime(2020, 1, 1, 8, 4, tzinfo=UTC)
        )
        self.assertEqual(snapshot["candidate"], summary)
        self.assertEqual(snapshot["stages"]["software"]["status"], "passed")
        self.assertEqual(snapshot["stages"]["test_firmware"]["status"], "waived")
        self.assertEqual(snapshot["stages"]["vehicle"]["status"], "open")

        for field, value in (
            ("target", "outdoor"),
            ("version", "2.2.0.6"),
            ("release_sequence", 8),
            ("file_size", summary["file_size"] + 1),
            ("sha256", "0" * 64),
            ("mandatory", True),
        ):
            with self.subTest(field=field):
                altered = dict(summary)
                altered[field] = value
                altered_receipt = dict(receipt)
                altered_receipt["candidate"] = altered
                self.receipt.write_text(json.dumps(altered_receipt), encoding="utf-8")
                with self.assertRaises(ReleaseAcceptanceError):
                    validate_release_acceptance(
                        altered,
                        self.receipt,
                        now=dt.datetime(2020, 1, 1, 8, 4, tzinfo=UTC),
                    )

        self.receipt.write_text(json.dumps(receipt), encoding="utf-8")
        evidence.unlink()
        with self.assertRaises(ReleaseAcceptanceError):
            validate_release_acceptance(
                summary, self.receipt, now=dt.datetime(2020, 1, 1, 8, 4, tzinfo=UTC)
            )


class BasicSleepFixExceptionTests(unittest.TestCase):
    setUp = ReleaseAcceptanceTests.setUp
    tearDown = ReleaseAcceptanceTests.tearDown
    _write_receipt = ReleaseAcceptanceTests._write_receipt

    def _basic_exception_receipt(self):
        self.summary = dict(release_acceptance._BASIC_EXCEPTION_CANDIDATE)
        self._write_receipt()
        raw = json.loads(self.receipt.read_text())
        raw["schema_version"] = 2
        path = self.root / "vehicle.txt"
        path.write_text("Nicht durchgefuehrt: neuer Fahrzeugtest durch Nutzer ausdruecklich ausgelassen.")
        raw["stages"]["vehicle"].update(status="waived", tested_by="not tested", completed_at=None,
            evidence_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        authorization = self.root / "authorization.txt"
        authorization.write_text(release_acceptance._BASIC_EXCEPTION_REASON)
        raw["approval"] = {"status": "approved_by_exception", "approved_by": "Bastian Schnier", "approved_at": "2020-01-01T08:03:00+00:00"}
        raw["exception"] = {"exception_id": release_acceptance._BASIC_EXCEPTION_ID,
            "reason": release_acceptance._BASIC_EXCEPTION_REASON, "evidence_file": authorization.name,
            "evidence_sha256": hashlib.sha256(authorization.read_bytes()).hexdigest()}
        self.receipt.write_text(json.dumps(raw))
        return raw

    def test_basic_waives_only_vehicle_for_exact_signed_bin(self):
        self._basic_exception_receipt()
        result = validate_release_acceptance(self.summary, self.receipt)
        self.assertEqual(result["stages"]["test_firmware"]["status"], "passed")
        self.assertEqual(result["stages"]["vehicle"]["status"], "waived")
        self.assertIsNone(result["stages"]["vehicle"]["completed_at"])

    def test_basic_waiver_cannot_move_to_other_artifact(self):
        raw = self._basic_exception_receipt()
        for field, value in (("target", "outdoor"), ("version", "2.2.0.3"), ("release_sequence", 4),
                             ("file_size", 999441), ("sha256", "0" * 64), ("mandatory", True)):
            with self.subTest(field=field):
                summary = {**self.summary, field: value}
                self.receipt.write_text(json.dumps({**raw, "candidate": summary}))
                with self.assertRaises(ReleaseAcceptanceError):
                    validate_release_acceptance(summary, self.receipt)

    def test_basic_requires_hardware_and_does_not_claim_vehicle_passed(self):
        for stage, status in (("test_firmware", "waived"), ("vehicle", "passed"), ("vehicle", "open")):
            with self.subTest(stage=stage, status=status):
                raw = self._basic_exception_receipt()
                raw["stages"][stage]["status"] = status
                self.receipt.write_text(json.dumps(raw))
                with self.assertRaises(ReleaseAcceptanceError):
                    validate_release_acceptance(self.summary, self.receipt)


if __name__ == "__main__":
    unittest.main()
