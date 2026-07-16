#!/usr/bin/env python3

from __future__ import annotations

import argparse
import getpass
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from release_signing import (
    KEYCHAIN_SERVICE,
    ReleaseManifest,
    SigningConfig,
    SigningError,
    assert_p256_public_key,
    public_key_fingerprint,
    read_keychain_passphrase,
    sign_manifest,
)


ROOT = Path(__file__).resolve().parent
DEFAULT_KEY_ROOT = (
    Path.home() / "Library" / "Application Support" / "CampClimate" / "OTA Signing"
)


def is_inside_repository(path: Path) -> bool:
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(ROOT.resolve())
        return True
    except ValueError:
        return False


def run_checked(command: list[str], env: dict[str, str] | None = None) -> None:
    try:
        subprocess.run(command, check=True, env=env)
    except FileNotFoundError as exc:
        raise SigningError(f"Programm nicht gefunden: {command[0]}") from exc
    except subprocess.CalledProcessError as exc:
        raise SigningError(
            f"Befehl fehlgeschlagen (Exit-Code {exc.returncode}): {command[0]}"
        ) from exc


def prompt_new_passphrase() -> str:
    first = getpass.getpass(
        "Neue Passphrase fuer den Produktionsschluessel "
        "(am besten aus der Passwort-App): "
    )
    if len(first) < 20:
        raise SigningError("Die Passphrase muss mindestens 20 Zeichen lang sein.")
    second = getpass.getpass("Passphrase wiederholen: ")
    if first != second:
        raise SigningError("Die Passphrasen stimmen nicht ueberein.")
    return first


def generate_key_pair(output_dir: Path, purpose: str) -> tuple[Path, Path, str, str]:
    output_dir = output_dir.expanduser().resolve()
    if is_inside_repository(output_dir):
        raise SigningError(
            "Signaturschluessel duerfen nicht innerhalb des Publisher-Repositories liegen."
        )
    output_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(output_dir, 0o700)
    if any(output_dir.iterdir()):
        raise SigningError(
            f"Zielordner ist nicht leer. Bitte einen neuen Ordner verwenden: {output_dir}"
        )

    passphrase = prompt_new_passphrase()
    child_env = os.environ.copy()
    child_env["CAMPCLIMATE_NEW_KEY_PASSPHRASE"] = passphrase

    with tempfile.TemporaryDirectory(prefix="campclimate-keygen-") as temp_dir:
        temporary_plain_private = Path(temp_dir) / "plain-private.pem"
        temporary_private = Path(temp_dir) / "private.pem"
        temporary_public = Path(temp_dir) / "public.pem"
        run_checked(
            [
                "openssl",
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
                str(temporary_plain_private),
            ]
        )
        os.chmod(temporary_plain_private, 0o600)
        run_checked(
            [
                "openssl",
                "pkcs8",
                "-topk8",
                "-v2",
                "aes-256-cbc",
                "-in",
                str(temporary_plain_private),
                "-passout",
                "env:CAMPCLIMATE_NEW_KEY_PASSPHRASE",
                "-out",
                str(temporary_private),
            ],
            env=child_env,
        )
        temporary_plain_private.unlink()
        run_checked(
            [
                "openssl",
                "pkey",
                "-in",
                str(temporary_private),
                "-passin",
                "env:CAMPCLIMATE_NEW_KEY_PASSPHRASE",
                "-pubout",
                "-out",
                str(temporary_public),
            ],
            env=child_env,
        )

        fingerprint = public_key_fingerprint(temporary_public)
        key_id = f"{purpose}-p256-{fingerprint[:16]}"
        private_path = output_dir / f"{key_id}-private.pem"
        public_path = output_dir / f"{key_id}-public.pem"
        shutil.copy2(temporary_private, private_path)
        shutil.copy2(temporary_public, public_path)

    os.chmod(private_path, 0o600)
    os.chmod(public_path, 0o644)

    smoke_manifest = ReleaseManifest(
        target="central",
        version="0.0.0-key-test",
        release_sequence=1,
        file_size_bytes=1,
        sha256="0" * 64,
        signing_key_id=key_id,
    )
    sign_manifest(
        smoke_manifest,
        SigningConfig(
            private_key_path=private_path,
            public_key_path=public_path,
            key_id=key_id,
        ),
        passphrase=passphrase,
    )
    return private_path, public_path, key_id, fingerprint


def store_keychain_passphrase(
    service: str,
    account: str,
    private_key_path: Path,
    public_key_path: Path,
) -> None:
    print(
        "macOS fragt jetzt die Passphrase ab. Verwende exakt die Passphrase, "
        "mit der die private PEM-Datei erzeugt wurde."
    )
    run_checked(
        [
            "security",
            "add-generic-password",
            "-U",
            "-s",
            service,
            "-a",
            account,
            "-l",
            f"CampClimate OTA signing key {account}",
            "-w",
        ]
    )
    passphrase = read_keychain_passphrase(service, account)
    sign_manifest(
        ReleaseManifest(
            target="central",
            version="0.0.0-keychain-test",
            release_sequence=1,
            file_size_bytes=1,
            sha256="0" * 64,
            signing_key_id=account,
        ),
        SigningConfig(
            private_key_path=private_key_path.expanduser(),
            public_key_path=public_key_path.expanduser(),
            key_id=account,
            keychain_service=service,
            keychain_account=account,
        ),
        passphrase=passphrase,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Sichere Einrichtung der CampClimate OTA-Signaturschluessel."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate_parser = subparsers.add_parser(
        "generate",
        help="Verschluesseltes P-256-Schluesselpaar ausserhalb des Repositories erzeugen.",
    )
    generate_parser.add_argument(
        "--purpose",
        choices=("production", "test"),
        default="production",
    )
    generate_parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help=f"Neuer leerer Zielordner (Standard unter {DEFAULT_KEY_ROOT}).",
    )

    keychain_parser = subparsers.add_parser(
        "store-passphrase",
        help="Passphrase interaktiv und ohne Kommandozeilen-Klartext im Schluesselbund speichern.",
    )
    keychain_parser.add_argument("--key-id", required=True)
    keychain_parser.add_argument("--service", default=KEYCHAIN_SERVICE)
    keychain_parser.add_argument("--private-key", required=True, type=Path)
    keychain_parser.add_argument("--public-key", required=True, type=Path)

    inspect_parser = subparsers.add_parser(
        "inspect",
        help="Fingerprint und vorgeschlagene Key-ID eines oeffentlichen Schluessels anzeigen.",
    )
    inspect_parser.add_argument("public_key", type=Path)
    inspect_parser.add_argument(
        "--purpose",
        choices=("production", "test"),
        default="production",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "generate":
            if args.output_dir is None:
                suffix = "production-p256-v1" if args.purpose == "production" else "test-p256-v1"
                output_dir = DEFAULT_KEY_ROOT / suffix
            else:
                output_dir = args.output_dir
            private_path, public_path, key_id, fingerprint = generate_key_pair(
                output_dir,
                args.purpose,
            )
            print()
            print("Schluesselpaar erzeugt und Signatur-Gegenprobe erfolgreich.")
            print(f"Key-ID:      {key_id}")
            print(f"Fingerprint: {fingerprint}")
            print(f"Privat:      {private_path}")
            print(f"Oeffentlich: {public_path}")
            print()
            print("Naechster Schritt:")
            print(
                "  python3 signing_key_tool.py store-passphrase "
                f'--key-id "{key_id}" '
                f'--private-key "{private_path}" '
                f'--public-key "{public_path}"'
            )
            print()
            print("Danach in env eintragen:")
            print("  OTA_SIGNING_MODE=required")
            print(f"  OTA_SIGNING_KEY_ID={key_id}")
            print(f"  OTA_SIGNING_PRIVATE_KEY={private_path}")
            print(f"  OTA_SIGNING_PUBLIC_KEY={public_path}")
            return 0

        if args.command == "store-passphrase":
            store_keychain_passphrase(
                args.service,
                args.key_id,
                args.private_key,
                args.public_key,
            )
            print(
                f"Passphrase ist fuer {args.service}/{args.key_id} im Schluesselbund "
                "gespeichert und passt zum privaten Schluessel."
            )
            return 0

        if args.command == "inspect":
            assert_p256_public_key(args.public_key.expanduser())
            fingerprint = public_key_fingerprint(args.public_key.expanduser())
            print(f"Fingerprint: {fingerprint}")
            print(f"Key-ID:      {args.purpose}-p256-{fingerprint[:16]}")
            return 0

        raise SigningError(f"Unbekannter Befehl: {args.command}")
    except SigningError as exc:
        print(f"Fehler: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
