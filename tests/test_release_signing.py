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
        firmware.write_bytes(b"CampClimate signed firmware test")
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
                target="central",
                version="2.0.1.10",
                notes="Test",
                mandatory=False,
                release_sequence=10,
                artifact_origin="build",
            )
        self.assertTrue(summary["signed"])
        self.assertEqual(summary["signing_key_id"], self.key_id)

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
                    target="central",
                    version="2.0.1.10",
                    notes="Test",
                    mandatory=False,
                    release_sequence=10,
                    artifact_origin="existing",
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


if __name__ == "__main__":
    unittest.main()
