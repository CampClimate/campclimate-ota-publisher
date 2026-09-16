from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import publisher
import signing_key_tool
from release_signing import (
    ReleaseManifest,
    SignedReleaseManifest,
    SigningConfig,
    SigningError,
    public_key_fingerprint,
    sign_manifest,
    verify_manifest,
)


OPENSSL_AVAILABLE = shutil.which("openssl") is not None


@unittest.skipUnless(OPENSSL_AVAILABLE, "OpenSSL ist fuer Signaturtests erforderlich.")
class ReleaseSigningTests(unittest.TestCase):
    PASSPHRASE = "campclimate-test-passphrase-only"

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="campclimate-signing-tests-")
        self.root = Path(self.temp_dir.name)
        plain_private_key = self.root / "plain-private.pem"
        self.private_key = self.root / "private.pem"
        self.public_key = self.root / "public.pem"
        child_env = os.environ.copy()
        child_env["TEST_KEY_PASSPHRASE"] = self.PASSPHRASE
        subprocess.run(
            [
                "openssl",
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
                str(plain_private_key),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        subprocess.run(
            [
                "openssl",
                "pkcs8",
                "-topk8",
                "-v2",
                "aes-256-cbc",
                "-in",
                str(plain_private_key),
                "-passout",
                "env:TEST_KEY_PASSPHRASE",
                "-out",
                str(self.private_key),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=child_env,
        )
        plain_private_key.unlink()
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(self.private_key),
                "-passin",
                "env:TEST_KEY_PASSPHRASE",
                "-pubout",
                "-out",
                str(self.public_key),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=child_env,
        )
        fingerprint = public_key_fingerprint(self.public_key)
        self.key_id = f"test-p256-{fingerprint[:16]}"
        self.config = SigningConfig(
            private_key_path=self.private_key,
            public_key_path=self.public_key,
            key_id=self.key_id,
        )
        self.manifest = ReleaseManifest(
            target="central",
            version="2.0.1.10",
            release_sequence=10,
            file_size_bytes=123456,
            sha256="ab" * 32,
            signing_key_id=self.key_id,
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_canonical_manifest_is_stable(self) -> None:
        self.assertEqual(
            self.manifest.canonical_text(),
            (
                "campclimate-firmware-release\n"
                "manifest_version=1\n"
                "signature_algorithm=ecdsa-p256-sha256\n"
                f"signing_key_id={self.key_id}\n"
                "target=central\n"
                "version=2.0.1.10\n"
                "release_sequence=10\n"
                "file_size_bytes=123456\n"
                f"sha256={'ab' * 32}\n"
            ),
        )

    def test_sign_and_verify(self) -> None:
        signed = sign_manifest(
            self.manifest,
            self.config,
            passphrase=self.PASSPHRASE,
        )
        self.assertTrue(signed.signature_base64)
        verify_manifest(signed, self.public_key)

    def test_changed_manifest_is_rejected(self) -> None:
        signed = sign_manifest(
            self.manifest,
            self.config,
            passphrase=self.PASSPHRASE,
        )
        changed = SignedReleaseManifest(
            manifest=ReleaseManifest(
                target="basic",
                version=self.manifest.version,
                release_sequence=self.manifest.release_sequence,
                file_size_bytes=self.manifest.file_size_bytes,
                sha256=self.manifest.sha256,
                signing_key_id=self.key_id,
            ),
            signature_base64=signed.signature_base64,
        )
        with self.assertRaises(SigningError):
            verify_manifest(changed, self.public_key)

    def test_invalid_manifest_fields_are_rejected(self) -> None:
        with self.assertRaises(SigningError):
            ReleaseManifest(
                target="central\nadmin=true",
                version="2.0.0",
                release_sequence=1,
                file_size_bytes=1,
                sha256="0" * 64,
                signing_key_id=self.key_id,
            ).canonical_text()
        with self.assertRaises(SigningError):
            ReleaseManifest(
                target="central",
                version="2.0.0",
                release_sequence=0,
                file_size_bytes=1,
                sha256="0" * 64,
                signing_key_id=self.key_id,
            ).canonical_text()

    def test_publisher_prepares_signed_release_and_detects_tampering(self) -> None:
        firmware = self.root / "firmware.bin"
        firmware.write_bytes(
            b"CampClimate signed firmware test"
            + publisher.RELEASE_SEQUENCE_MARKER
            + (10).to_bytes(8, "little")
        )
        environment = {
            "SUPABASE_URL": "https://example.supabase.co",
            "SUPABASE_SERVICE_ROLE_KEY": "test-service-role",
            "SUPABASE_STORAGE_BUCKET": "firmware",
            "OTA_SIGNING_MODE": "required",
            "OTA_SIGNING_PRIVATE_KEY": str(self.private_key),
            "OTA_SIGNING_PUBLIC_KEY": str(self.public_key),
            "OTA_SIGNING_KEY_ID": self.key_id,
        }
        with mock.patch.dict(os.environ, environment, clear=False), mock.patch(
            "release_signing.read_keychain_passphrase",
            return_value=self.PASSPHRASE,
        ):
            summary = publisher.prepare_release(
                file_path=firmware,
                target="basic",
                version="2.0.1.10",
                notes="Test",
                mandatory=False,
                release_sequence=10,
                artifact_origin="build",
            )
        self.assertTrue(summary["signed"])
        self.assertEqual(summary["signing_key_id"], self.key_id)
        self.assertEqual(summary["embedded_release_sequence"], 10)

        tampered_summary = dict(summary)
        original_signature = str(tampered_summary["signature_base64"])
        replacement = "A" if original_signature[0] != "A" else "B"
        tampered_summary["signature_base64"] = replacement + original_signature[1:]
        with mock.patch.dict(os.environ, environment, clear=False):
            with self.assertRaises(RuntimeError):
                publisher._verify_prepared_signature(tampered_summary)

        firmware.write_bytes(b"manipulated")
        with self.assertRaises(RuntimeError):
            publisher._assert_prepared_artifact_unchanged(summary)

    def test_existing_binary_is_blocked_for_required_signing(self) -> None:
        firmware = self.root / "firmware.bin"
        firmware.write_bytes(b"existing binary")
        environment = {
            "SUPABASE_URL": "https://example.supabase.co",
            "SUPABASE_SERVICE_ROLE_KEY": "test-service-role",
            "OTA_SIGNING_MODE": "required",
            "OTA_SIGNING_PRIVATE_KEY": str(self.private_key),
            "OTA_SIGNING_PUBLIC_KEY": str(self.public_key),
            "OTA_SIGNING_KEY_ID": self.key_id,
            "OTA_ALLOW_EXISTING_SIGNED_BIN": "0",
        }
        with mock.patch.dict(os.environ, environment, clear=False):
            with self.assertRaises(RuntimeError):
                publisher.prepare_release(
                    file_path=firmware,
                    target="basic",
                    version="2.0.1.10",
                    notes="Test",
                    mandatory=False,
                    release_sequence=10,
                    artifact_origin="existing",
                )

    def test_signed_release_rejects_missing_or_mismatched_binary_sequence(self) -> None:
        environment = {
            "SUPABASE_URL": "https://example.supabase.co",
            "SUPABASE_SERVICE_ROLE_KEY": "test-service-role",
            "OTA_SIGNING_MODE": "required",
            "OTA_SIGNING_PRIVATE_KEY": str(self.private_key),
            "OTA_SIGNING_PUBLIC_KEY": str(self.public_key),
            "OTA_SIGNING_KEY_ID": self.key_id,
        }
        missing = self.root / "missing-marker.bin"
        missing.write_bytes(b"firmware without build identity")
        mismatched = self.root / "mismatched-marker.bin"
        mismatched.write_bytes(
            b"firmware"
            + publisher.RELEASE_SEQUENCE_MARKER
            + (9).to_bytes(8, "little")
        )

        with mock.patch.dict(os.environ, environment, clear=False):
            with self.assertRaisesRegex(RuntimeError, "genau eine"):
                publisher.prepare_release(
                    file_path=missing,
                    target="basic",
                    version="2.0.1.10",
                    notes="Test",
                    mandatory=False,
                    release_sequence=10,
                    artifact_origin="build",
                )
            with self.assertRaisesRegex(RuntimeError, "BIN=9"):
                publisher.prepare_release(
                    file_path=mismatched,
                    target="basic",
                    version="2.0.1.10",
                    notes="Test",
                    mandatory=False,
                    release_sequence=10,
                    artifact_origin="build",
                )

    def test_key_tool_generates_encrypted_pair_outside_repository(self) -> None:
        output_dir = self.root / "generated-production-key"
        with mock.patch(
            "signing_key_tool.prompt_new_passphrase",
            return_value=self.PASSPHRASE,
        ):
            private_path, public_path, key_id, fingerprint = (
                signing_key_tool.generate_key_pair(output_dir, "production")
            )
        self.assertTrue(private_path.is_file())
        self.assertTrue(public_path.is_file())
        self.assertEqual(key_id, f"production-p256-{fingerprint[:16]}")
        self.assertNotIn("BEGIN EC PRIVATE KEY", private_path.read_text(encoding="utf-8"))
        self.assertIn("BEGIN ENCRYPTED PRIVATE KEY", private_path.read_text(encoding="utf-8"))

    def test_ssl_context_verifies_certificates_by_default(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"SUPABASE_INSECURE_SSL": "0"},
            clear=False,
        ):
            context = publisher.make_ssl_context()
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, 2)

    def test_release_uses_content_addressed_storage_path(self) -> None:
        firmware = self.root / "firmware.bin"
        firmware.write_bytes(b"content addressed firmware")
        summary = publisher.build_release_summary(
            supabase_url="https://example.supabase.co",
            bucket="firmware",
            file_path=firmware,
            target="Central",
            version="2.0.1.10",
            notes="Test",
            mandatory=False,
        )
        expected_sha256 = publisher.sha256_of_file(firmware)
        self.assertEqual(summary["target"], "central")
        self.assertEqual(
            summary["object_path"],
            f"central/sha256/{expected_sha256}.bin",
        )
        self.assertEqual(
            summary["storage_path"],
            f"firmware/central/sha256/{expected_sha256}.bin",
        )

    def test_immutable_upload_never_enables_upsert_and_always_reads_back(self) -> None:
        firmware = self.root / "firmware.bin"
        firmware.write_bytes(b"immutable upload")
        digest = publisher.sha256_of_file(firmware)
        with mock.patch("publisher.upload_file") as upload, mock.patch(
            "publisher.verify_remote_artifact"
        ) as verify:
            publisher.upload_immutable_artifact(
                "https://example.supabase.co",
                "service-role",
                "firmware",
                f"central/sha256/{digest}.bin",
                firmware,
                firmware.stat().st_size,
                digest,
            )
        upload.assert_called_once_with(
            "https://example.supabase.co",
            "service-role",
            "firmware",
            f"central/sha256/{digest}.bin",
            firmware,
        )
        verify.assert_called_once()

    def test_duplicate_content_object_is_only_reused_after_readback(self) -> None:
        firmware = self.root / "firmware.bin"
        firmware.write_bytes(b"already uploaded")
        digest = publisher.sha256_of_file(firmware)
        duplicate = publisher.HttpRequestError(
            409,
            "https://example.supabase.co/storage/v1/object/firmware/test.bin",
            '{"error":"Duplicate","message":"The resource already exists"}',
        )
        with mock.patch(
            "publisher.upload_file",
            side_effect=duplicate,
        ), mock.patch("publisher.verify_remote_artifact") as verify:
            publisher.upload_immutable_artifact(
                "https://example.supabase.co",
                "service-role",
                "firmware",
                f"central/sha256/{digest}.bin",
                firmware,
                firmware.stat().st_size,
                digest,
            )
        verify.assert_called_once()

    def test_remote_artifact_mismatch_is_rejected(self) -> None:
        with mock.patch(
            "publisher.download_public_object",
            return_value=b"tampered remote firmware",
        ):
            with self.assertRaises(RuntimeError):
                publisher.verify_remote_artifact(
                    "https://example.supabase.co",
                    "service-role",
                    "firmware",
                    "central/sha256/test.bin",
                    len(b"expected firmware"),
                    publisher.hashlib.sha256(b"expected firmware").hexdigest(),
                )

    def test_signed_release_sequence_must_increase(self) -> None:
        summary = {
            "signed": True,
            "target": "central",
            "release_sequence": 10,
        }
        latest = {
            "id": "latest-release",
            "version": "2.0.1.9",
            "release_sequence": 10,
            "published": True,
        }
        with mock.patch(
            "publisher.fetch_latest_signed_release",
            return_value=latest,
        ):
            with self.assertRaises(RuntimeError):
                publisher._assert_release_sequence_monotonic(
                    "https://example.supabase.co",
                    "service-role",
                    summary,
                    None,
                )

        summary["release_sequence"] = 11
        with mock.patch(
            "publisher.fetch_latest_signed_release",
            return_value=latest,
        ):
            publisher._assert_release_sequence_monotonic(
                "https://example.supabase.co",
                "service-role",
                summary,
                None,
            )

    def test_exact_published_release_is_idempotent_but_cannot_be_changed(self) -> None:
        summary = {
            "signed": False,
            "target": "central",
            "version": "2.0.1.10",
            "notes": "Idempotent test",
            "storage_path": "firmware/central/sha256/" + ("ab" * 32) + ".bin",
            "file_size": 123,
            "sha256": "ab" * 32,
            "mandatory": False,
        }
        existing = {
            "id": "existing-release",
            "target": summary["target"],
            "version": summary["version"],
            "notes": summary["notes"],
            "storage_path": summary["storage_path"],
            "file_size_bytes": summary["file_size"],
            "sha256": summary["sha256"],
            "mandatory": summary["mandatory"],
            "published": True,
        }
        publisher._adopt_existing_release(summary, existing)

        changed = dict(existing)
        changed["sha256"] = "cd" * 32
        with self.assertRaises(RuntimeError):
            publisher._adopt_existing_release(summary, changed)

    def test_publish_is_staged_and_only_visible_after_readback(self) -> None:
        firmware = self.root / "firmware.bin"
        firmware.write_bytes(b"staged publish")
        environment = {
            "SUPABASE_URL": "https://example.supabase.co",
            "SUPABASE_SERVICE_ROLE_KEY": "service-role",
            "SUPABASE_STORAGE_BUCKET": "firmware",
            "OTA_SIGNING_MODE": "disabled",
        }
        with mock.patch.dict(os.environ, environment, clear=False):
            summary = publisher.prepare_release(
                file_path=firmware,
                target="basic",
                version="2.0.1.10",
                notes="Staged test",
                mandatory=False,
            )

        def release_row(published: bool) -> dict[str, object]:
            return {
                "id": "release-id",
                "target": summary["target"],
                "version": summary["version"],
                "notes": summary["notes"],
                "storage_path": summary["storage_path"],
                "file_size_bytes": summary["file_size"],
                "sha256": summary["sha256"],
                "mandatory": summary["mandatory"],
                "published": published,
                "manifest_version": None,
                "signature_algorithm": None,
                "signing_key_id": None,
                "release_sequence": None,
                "signature_base64": None,
                "created_at": "2026-07-16T00:00:00Z",
            }

        events: list[str] = []
        archived_path = self.root / "archive" / "firmware.bin"
        record_path = self.root / "archive" / "firmware.bin.release.json"
        with mock.patch.dict(os.environ, environment, clear=False), mock.patch(
            "publisher.preflight_release",
            side_effect=lambda *_args: events.append("preflight"),
        ), mock.patch(
            "publisher.upload_immutable_artifact",
            side_effect=lambda *_args: events.append("upload"),
        ), mock.patch(
            "publisher.insert_unpublished_release",
            side_effect=lambda *_args: (
                events.append("insert-unpublished"),
                release_row(False),
            )[1],
        ), mock.patch(
            "publisher.fetch_release_by_id",
            side_effect=lambda *_args: (
                events.append("database-readback"),
                release_row(False),
            )[1],
        ), mock.patch(
            "publisher.mark_release_published",
            side_effect=lambda *_args: (
                events.append("publish"),
                release_row(True),
            )[1],
        ), mock.patch(
            "publisher.archive_uploaded_file",
            return_value=archived_path,
        ), mock.patch(
            "publisher.archive_release_record",
            return_value=record_path,
        ):
            result = publisher.publish_prepared_release(summary)

        self.assertEqual(
            events,
            [
                "preflight",
                "upload",
                "insert-unpublished",
                "database-readback",
                "publish",
            ],
        )
        self.assertTrue(result["release"]["published"])


if __name__ == "__main__":
    unittest.main()
