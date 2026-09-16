from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import publisher
from release_signing import SigningError, public_key_fingerprint


OPENSSL_AVAILABLE = bool(__import__("shutil").which("openssl"))


@unittest.skipUnless(OPENSSL_AVAILABLE, "OpenSSL ist fuer Signaturtests erforderlich.")
class CentralSecureBootPublishTests(unittest.TestCase):
    PASSPHRASE = "campclimate-central-publisher-test-only"
    RELEASE_SEQUENCE = 23

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="central-sbv2-publisher-")
        self.root = Path(self.temp_dir.name)
        self.source = self.root / "central.bin"
        # The Central linker can discard the legacy Basic sequence marker.
        # Only the image-tool-verified Central descriptor is authoritative.
        self.source.write_bytes(b"unsigned-central-image-without-legacy-marker")
        self.rsa_key = self.root / "central-rsa3072-private.pem"
        self.rsa_key.write_text("test-only-rsa-placeholder\n", encoding="utf-8")
        self.rsa_key.chmod(0o600)

        plain_private_key = self.root / "manifest-plain-private.pem"
        self.manifest_private_key = self.root / "manifest-private.pem"
        self.manifest_public_key = self.root / "manifest-public.pem"
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
                str(self.manifest_private_key),
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
                str(self.manifest_private_key),
                "-passin",
                "env:TEST_KEY_PASSPHRASE",
                "-pubout",
                "-out",
                str(self.manifest_public_key),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=child_env,
        )
        fingerprint = public_key_fingerprint(self.manifest_public_key)
        self.manifest_key_id = f"test-p256-{fingerprint[:16]}"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def environment(self, *, signing_mode: str = "required") -> dict[str, str]:
        return {
            "SUPABASE_URL": "https://example.supabase.co",
            "SUPABASE_SERVICE_ROLE_KEY": "test-service-role",
            "SUPABASE_STORAGE_BUCKET": "firmware",
            "OTA_SIGNING_MODE": signing_mode,
            "OTA_SIGNING_PRIVATE_KEY": str(self.manifest_private_key),
            "OTA_SIGNING_PUBLIC_KEY": str(self.manifest_public_key),
            "OTA_SIGNING_KEY_ID": self.manifest_key_id,
            "OTA_ALLOW_EXISTING_SIGNED_BIN": "0",
            publisher.CENTRAL_SECURE_BOOT_PRIVATE_KEY_ENV: str(self.rsa_key),
        }

    def identity(self, *, signed: bool) -> dict[str, object]:
        return {
            "image_kind": "production",
            "hardware": "2.0",
            "release_sequence": self.RELEASE_SEQUENCE,
            "security_generation": 0,
            "policy_version": 1,
            "signature_present": signed,
            "signature_scheme": "rsa3072" if signed else None,
            "signature_verified": signed,
        }

    def fake_image_tool(self, calls: list[list[str]]):
        def invoke(arguments: list[str]) -> dict[str, object]:
            calls.append(list(arguments))
            if "--sign-key" in arguments:
                output = Path(arguments[arguments.index("--output") + 1])
                output.write_bytes(self.source.read_bytes() + b"rsa3072-signature-sector")
                output.chmod(0o600)
                return self.identity(signed=True)
            if "--verify-key" in arguments:
                return self.identity(signed=True)
            return self.identity(signed=False)

        return invoke

    def test_central_is_rsa_signed_before_manifest_hashing(self) -> None:
        calls: list[list[str]] = []
        environment = self.environment()
        with mock.patch.dict(os.environ, environment, clear=False), mock.patch(
            "publisher._run_central_image_tool",
            side_effect=self.fake_image_tool(calls),
        ), mock.patch(
            "release_signing.read_keychain_passphrase",
            return_value=self.PASSPHRASE,
        ):
            summary = publisher.prepare_release(
                file_path=self.source,
                target="central",
                version="2.0.1.23",
                notes="Secure Boot test",
                mandatory=False,
                release_sequence=self.RELEASE_SEQUENCE,
                artifact_origin="build",
            )
            signed_path = Path(summary["file_path"])
            self.assertTrue(signed_path.is_file())
            self.assertEqual(
                summary["sha256"], hashlib.sha256(signed_path.read_bytes()).hexdigest()
            )
            self.assertNotEqual(
                summary["sha256"], hashlib.sha256(self.source.read_bytes()).hexdigest()
            )
            self.assertTrue(summary["central_secure_boot_verified"])
            self.assertEqual(summary["central_image_kind"], "production")
            self.assertEqual(summary["central_signature_scheme"], "rsa3072")
            self.assertTrue(summary["signed"])
            publisher._verify_prepared_signature(summary)

        self.assertEqual(len(calls), 2)
        self.assertNotIn("--sign-key", calls[0])
        self.assertIn("--sign-key", calls[1])
        self.assertNotIn(str(self.rsa_key), repr(summary))
        staging_directory = Path(summary["_central_private_staging_dir"])
        publisher.cleanup_prepared_release(summary)
        self.assertFalse(staging_directory.exists())

    def test_basic_flow_never_invokes_central_image_tool(self) -> None:
        self.source.write_bytes(
            b"basic-image" + publisher.RELEASE_SEQUENCE_MARKER
            + self.RELEASE_SEQUENCE.to_bytes(8, "little")
        )
        environment = self.environment()
        with mock.patch.dict(os.environ, environment, clear=False), mock.patch(
            "publisher._run_central_image_tool"
        ) as image_tool, mock.patch(
            "release_signing.read_keychain_passphrase",
            return_value=self.PASSPHRASE,
        ):
            summary = publisher.prepare_release(
                file_path=self.source,
                target="basic",
                version="2.0.1.23",
                notes="Basic unchanged",
                mandatory=False,
                release_sequence=self.RELEASE_SEQUENCE,
                artifact_origin="build",
            )
        image_tool.assert_not_called()
        self.assertEqual(Path(summary["file_path"]), self.source)
        self.assertNotIn("central_secure_boot_verified", summary)

    def test_central_fails_closed_without_absolute_private_key(self) -> None:
        environment = self.environment()
        environment[publisher.CENTRAL_SECURE_BOOT_PRIVATE_KEY_ENV] = "relative/key.pem"
        with mock.patch.dict(os.environ, environment, clear=False):
            with self.assertRaisesRegex(RuntimeError, "absoluter Pfad"):
                publisher.prepare_release(
                    file_path=self.source,
                    target="central",
                    version="2.0.1.23",
                    notes="Must fail",
                    mandatory=False,
                    release_sequence=self.RELEASE_SEQUENCE,
                    artifact_origin="build",
                )

    def test_central_fails_closed_for_overly_open_private_key(self) -> None:
        self.rsa_key.chmod(0o644)
        with mock.patch.dict(os.environ, self.environment(), clear=False):
            with self.assertRaisesRegex(RuntimeError, "0600"):
                publisher.prepare_release(
                    file_path=self.source,
                    target="central",
                    version="2.0.1.23",
                    notes="Must fail",
                    mandatory=False,
                    release_sequence=self.RELEASE_SEQUENCE,
                    artifact_origin="build",
                )

    def test_tool_failure_does_not_expose_key_path(self) -> None:
        fake_tool = self.root / "image_tool.py"
        fake_tool.write_text("# test-only placeholder\n", encoding="utf-8")
        result = subprocess.CompletedProcess(
            args=["image_tool.py"],
            returncode=1,
            stdout="",
            stderr=f"failure while reading {self.rsa_key}",
        )
        with mock.patch.object(
            publisher, "CENTRAL_IMAGE_TOOL", fake_tool
        ), mock.patch("publisher.subprocess.run", return_value=result):
            with self.assertRaises(RuntimeError) as raised:
                publisher._run_central_image_tool(
                    [str(self.source), "--sign-key", str(self.rsa_key)]
                )
        self.assertNotIn(str(self.rsa_key), str(raised.exception))
        self.assertNotIn(str(self.rsa_key), repr(raised.exception))

    def test_publish_reverifies_and_cleans_private_artifact_on_failure(self) -> None:
        calls: list[list[str]] = []
        environment = self.environment(signing_mode="disabled")
        with mock.patch.dict(os.environ, environment, clear=False), mock.patch(
            "publisher._run_central_image_tool",
            side_effect=self.fake_image_tool(calls),
        ):
            summary = publisher.prepare_release(
                file_path=self.source,
                target="central",
                version="2.0.1.23",
                notes="Cleanup test",
                mandatory=False,
                release_sequence=self.RELEASE_SEQUENCE,
                artifact_origin="build",
            )
            staging_directory = Path(summary["_central_private_staging_dir"])
            with mock.patch(
                "publisher.preflight_release", side_effect=RuntimeError("offline test")
            ):
                with self.assertRaisesRegex(RuntimeError, "offline test"):
                    publisher.publish_prepared_release(summary)

        self.assertTrue(any("--verify-key" in call for call in calls))
        self.assertFalse(staging_directory.exists())

    def test_manifest_failure_cleans_private_artifact(self) -> None:
        calls: list[list[str]] = []
        environment = self.environment()
        with mock.patch.dict(os.environ, environment, clear=False), mock.patch(
            "publisher._run_central_image_tool",
            side_effect=self.fake_image_tool(calls),
        ), mock.patch(
            "publisher.signing_config_from_values",
            side_effect=SigningError("test-only manifest failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "Firmware-Signatur"):
                publisher.prepare_release(
                    file_path=self.source,
                    target="central",
                    version="2.0.1.23",
                    notes="Cleanup test",
                    mandatory=False,
                    release_sequence=self.RELEASE_SEQUENCE,
                    artifact_origin="build",
                )

        self.assertEqual(list(publisher.DROP_DIR.glob(".central-sbv2-*")), [])


if __name__ == "__main__":
    unittest.main()
