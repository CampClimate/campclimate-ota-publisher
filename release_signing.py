#!/usr/bin/env python3

from __future__ import annotations

import base64
import binascii
from dataclasses import asdict, dataclass
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Callable, Mapping


MANIFEST_DOMAIN = "campclimate-firmware-release"
MANIFEST_VERSION = 1
SIGNATURE_ALGORITHM = "ecdsa-p256-sha256"
KEYCHAIN_SERVICE = "de.campclimate.ota-signing"

_HEX_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$")


class SigningError(RuntimeError):
    pass


@dataclass(frozen=True)
class ReleaseManifest:
    target: str
    version: str
    release_sequence: int
    file_size_bytes: int
    sha256: str
    signing_key_id: str
    manifest_version: int = MANIFEST_VERSION
    signature_algorithm: str = SIGNATURE_ALGORITHM

    def validate(self) -> None:
        if self.manifest_version != MANIFEST_VERSION:
            raise SigningError(
                f"Nicht unterstuetzte Manifest-Version: {self.manifest_version}"
            )
        if self.signature_algorithm != SIGNATURE_ALGORITHM:
            raise SigningError(
                f"Nicht unterstuetzter Signaturalgorithmus: {self.signature_algorithm}"
            )
        if self.target not in {"basic", "central"}:
            raise SigningError("Target muss 'basic' oder 'central' sein.")
        if not _VERSION_RE.fullmatch(self.version):
            raise SigningError(
                "Version darf nur Buchstaben, Zahlen, Punkt, Unterstrich, Plus und Minus enthalten."
            )
        if self.release_sequence < 1:
            raise SigningError("Release-Sequenz muss groesser oder gleich 1 sein.")
        if self.file_size_bytes < 1:
            raise SigningError("Firmware-Dateigroesse muss groesser als 0 sein.")
        if not _HEX_SHA256_RE.fullmatch(self.sha256):
            raise SigningError("SHA256 muss aus genau 64 kleingeschriebenen Hex-Zeichen bestehen.")
        if not _KEY_ID_RE.fullmatch(self.signing_key_id):
            raise SigningError(
                "Key-ID darf nur kleingeschriebene Buchstaben, Zahlen, Punkt, "
                "Unterstrich und Minus enthalten."
            )

    def canonical_text(self) -> str:
        self.validate()
        return (
            f"{MANIFEST_DOMAIN}\n"
            f"manifest_version={self.manifest_version}\n"
            f"signature_algorithm={self.signature_algorithm}\n"
            f"signing_key_id={self.signing_key_id}\n"
            f"target={self.target}\n"
            f"version={self.version}\n"
            f"release_sequence={self.release_sequence}\n"
            f"file_size_bytes={self.file_size_bytes}\n"
            f"sha256={self.sha256}\n"
        )

    def canonical_bytes(self) -> bytes:
        return self.canonical_text().encode("utf-8")

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class SignedReleaseManifest:
    manifest: ReleaseManifest
    signature_base64: str

    def to_dict(self) -> dict[str, object]:
        values = self.manifest.to_dict()
        values["signature_base64"] = self.signature_base64
        values["canonical_manifest"] = self.manifest.canonical_text()
        return values


@dataclass(frozen=True)
class SigningConfig:
    private_key_path: Path
    public_key_path: Path
    key_id: str
    keychain_service: str = KEYCHAIN_SERVICE
    keychain_account: str = ""

    def validate_paths(self) -> None:
        if not self.private_key_path.is_file():
            raise SigningError(
                f"Privater Signaturschluessel nicht gefunden: {self.private_key_path}"
            )
        if not self.public_key_path.is_file():
            raise SigningError(
                f"Oeffentlicher Signaturschluessel nicht gefunden: {self.public_key_path}"
            )
        if not _KEY_ID_RE.fullmatch(self.key_id):
            raise SigningError(f"Ungueltige OTA_SIGNING_KEY_ID: {self.key_id}")

    @property
    def resolved_keychain_account(self) -> str:
        return self.keychain_account or self.key_id


def signing_config_from_values(
    value: Callable[[str, str], str],
) -> SigningConfig:
    private_key = value("OTA_SIGNING_PRIVATE_KEY", "").strip()
    public_key = value("OTA_SIGNING_PUBLIC_KEY", "").strip()
    key_id = value("OTA_SIGNING_KEY_ID", "").strip()
    service = value("OTA_SIGNING_KEYCHAIN_SERVICE", KEYCHAIN_SERVICE).strip()
    account = value("OTA_SIGNING_KEYCHAIN_ACCOUNT", key_id).strip()

    missing = [
        name
        for name, configured in (
            ("OTA_SIGNING_PRIVATE_KEY", private_key),
            ("OTA_SIGNING_PUBLIC_KEY", public_key),
            ("OTA_SIGNING_KEY_ID", key_id),
        )
        if not configured
    ]
    if missing:
        raise SigningError(
            "Fehlende Signaturkonfiguration: " + ", ".join(missing)
        )

    return SigningConfig(
        private_key_path=Path(private_key).expanduser(),
        public_key_path=Path(public_key).expanduser(),
        key_id=key_id,
        keychain_service=service or KEYCHAIN_SERVICE,
        keychain_account=account or key_id,
    )


def _run(
    command: list[str],
    *,
    input_bytes: bytes | None = None,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            command,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            env=dict(env) if env is not None else None,
        )
    except FileNotFoundError as exc:
        raise SigningError(f"Programm nicht gefunden: {command[0]}") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode("utf-8", errors="replace").strip()
        if not detail:
            detail = exc.stdout.decode("utf-8", errors="replace").strip()
        raise SigningError(
            f"Signaturwerkzeug fehlgeschlagen ({command[0]}): {detail or 'unbekannter Fehler'}"
        ) from exc


def read_keychain_passphrase(
    service: str,
    account: str,
    *,
    security_bin: str = "security",
) -> str:
    result = _run(
        [
            security_bin,
            "find-generic-password",
            "-s",
            service,
            "-a",
            account,
            "-w",
        ]
    )
    passphrase = result.stdout.decode("utf-8").rstrip("\r\n")
    if not passphrase:
        raise SigningError(
            f"Leere Passphrase im macOS-Schluesselbund fuer {service}/{account}."
        )
    return passphrase


def public_key_fingerprint(
    public_key_path: Path,
    *,
    openssl_bin: str = "openssl",
) -> str:
    result = _run(
        [
            openssl_bin,
            "pkey",
            "-pubin",
            "-in",
            str(public_key_path),
            "-outform",
            "DER",
        ]
    )
    return hashlib.sha256(result.stdout).hexdigest()


def assert_p256_public_key(
    public_key_path: Path,
    *,
    openssl_bin: str = "openssl",
) -> None:
    result = _run(
        [
            openssl_bin,
            "ec",
            "-pubin",
            "-in",
            str(public_key_path),
            "-text",
            "-noout",
        ]
    )
    key_text = (result.stdout + result.stderr).decode("utf-8", errors="replace")
    if "prime256v1" not in key_text and "P-256" not in key_text:
        raise SigningError("Der oeffentliche Schluessel verwendet nicht die Kurve P-256.")


def _signature_der(signature_base64: str) -> bytes:
    try:
        signature = base64.b64decode(signature_base64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise SigningError("Signatur ist kein gueltiges Base64.") from exc
    if not signature:
        raise SigningError("Signatur darf nicht leer sein.")
    return signature


def sign_manifest(
    manifest: ReleaseManifest,
    config: SigningConfig,
    *,
    passphrase: str | None = None,
    openssl_bin: str = "openssl",
    security_bin: str = "security",
) -> SignedReleaseManifest:
    manifest.validate()
    config.validate_paths()
    assert_p256_public_key(config.public_key_path, openssl_bin=openssl_bin)

    secret = passphrase
    if secret is None:
        secret = read_keychain_passphrase(
            config.keychain_service,
            config.resolved_keychain_account,
            security_bin=security_bin,
        )
    if not secret:
        raise SigningError("Die Passphrase fuer den privaten Schluessel ist leer.")

    child_env = os.environ.copy()
    child_env["CAMPCLIMATE_OPENSSL_KEY_PASSPHRASE"] = secret
    with tempfile.TemporaryDirectory(prefix="campclimate-sign-") as temp_dir:
        manifest_path = Path(temp_dir) / "manifest.txt"
        manifest_path.write_bytes(manifest.canonical_bytes())
        result = _run(
            [
                openssl_bin,
                "dgst",
                "-sha256",
                "-sign",
                str(config.private_key_path),
                "-passin",
                "env:CAMPCLIMATE_OPENSSL_KEY_PASSPHRASE",
                str(manifest_path),
            ],
            env=child_env,
        )

    signature_base64 = base64.b64encode(result.stdout).decode("ascii")
    signed = SignedReleaseManifest(
        manifest=manifest,
        signature_base64=signature_base64,
    )
    verify_manifest(
        signed,
        config.public_key_path,
        openssl_bin=openssl_bin,
    )
    return signed


def verify_manifest(
    signed_manifest: SignedReleaseManifest,
    public_key_path: Path,
    *,
    openssl_bin: str = "openssl",
) -> None:
    signed_manifest.manifest.validate()
    if not public_key_path.is_file():
        raise SigningError(f"Oeffentlicher Schluessel nicht gefunden: {public_key_path}")
    assert_p256_public_key(public_key_path, openssl_bin=openssl_bin)
    signature = _signature_der(signed_manifest.signature_base64)

    with tempfile.TemporaryDirectory(prefix="campclimate-verify-") as temp_dir:
        manifest_path = Path(temp_dir) / "manifest.txt"
        signature_path = Path(temp_dir) / "signature.der"
        manifest_path.write_bytes(signed_manifest.manifest.canonical_bytes())
        signature_path.write_bytes(signature)
        _run(
            [
                openssl_bin,
                "dgst",
                "-sha256",
                "-verify",
                str(public_key_path),
                "-signature",
                str(signature_path),
                str(manifest_path),
            ]
        )
