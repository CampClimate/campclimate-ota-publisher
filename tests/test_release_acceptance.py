from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import publisher
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


if __name__ == "__main__":
    unittest.main()
