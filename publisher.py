#!/usr/bin/env python3

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

try:
    import certifi
except ImportError:
    certifi = None

from release_signing import (
    ReleaseManifest,
    SignedReleaseManifest,
    SigningError,
    public_key_fingerprint,
    sign_manifest,
    signing_config_from_values,
    verify_manifest,
)


ROOT = Path(__file__).resolve().parent
DROP_DIR = ROOT / "drop"
ARCHIVE_DIR = ROOT / "archive"
ENV_FILE = ROOT / "env"
DEFAULT_HTTP_TIMEOUT = 120
DEFAULT_HTTP_RETRIES = 3
DEFAULT_UPLOAD_TIMEOUT = 300
SIGNING_MODE_DISABLED = "disabled"
SIGNING_MODE_REQUIRED = "required"


def load_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def env_value(name: str, fallback: str = "") -> str:
    file_values = load_env_file(ENV_FILE)
    return os.environ.get(name, file_values.get(name, fallback))


def env_bool(name: str, fallback: bool = False) -> bool:
    default = "1" if fallback else "0"
    return env_value(name, default).strip().lower() in {
        "1", "true", "yes", "y", "on"
    }


def signing_mode() -> str:
    configured = env_value("OTA_SIGNING_MODE", SIGNING_MODE_DISABLED).strip().lower()
    aliases = {
        "off": SIGNING_MODE_DISABLED,
        "legacy": SIGNING_MODE_DISABLED,
        "on": SIGNING_MODE_REQUIRED,
    }
    mode = aliases.get(configured, configured)
    if mode not in {SIGNING_MODE_DISABLED, SIGNING_MODE_REQUIRED}:
        raise RuntimeError(
            "OTA_SIGNING_MODE muss 'disabled' oder 'required' sein."
        )
    return mode


def default_release_sequence(target: str) -> str:
    target_name = target.strip().upper()
    target_value = env_value(f"OTA_{target_name}_RELEASE_SEQUENCE", "").strip()
    return target_value or env_value("OTA_RELEASE_SEQUENCE", "").strip()


def prompt(text: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{text}{suffix}: ").strip()
    return value or default


def prompt_bool(text: str, default: bool = False) -> bool:
    default_text = "y" if default else "n"
    value = input(f"{text} [y/n] [{default_text}]: ").strip().lower()
    if not value:
        return default
    return value in {"y", "yes", "j", "ja", "1", "true"}


def discover_bin_files() -> list[Path]:
    return sorted([path for path in DROP_DIR.glob("*.bin") if path.is_file()])


def choose_file(files: list[Path]) -> Path:
    if len(files) == 1:
        file_path = files[0]
        print(f"Gefundene Datei: {file_path.name}")
        return file_path

    print("Mehrere BIN-Dateien gefunden:")
    for index, path in enumerate(files, start=1):
        size_kb = path.stat().st_size / 1024.0
        print(f"  {index}. {path.name} ({size_kb:.1f} KB)")

    while True:
        raw_choice = input("Welche Datei soll veroeffentlicht werden? [Nummer]: ").strip()
        try:
            choice = int(raw_choice)
        except ValueError:
            print("Bitte eine gueltige Nummer eingeben.")
            continue

        if 1 <= choice <= len(files):
            return files[choice - 1]

        print("Auswahl ausserhalb der Liste.")


def infer_target(file_name: str) -> str:
    lowered = file_name.lower()
    if lowered.startswith("central_"):
        return "central"
    if lowered.startswith("basic_"):
        return "basic"
    return ""


def infer_version(file_name: str) -> str:
    stem = Path(file_name).stem
    if "_" not in stem:
        return ""
    return stem.split("_", 1)[1]


def sha256_of_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(65536)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def slugify(text: str) -> str:
    cleaned = []
    for char in text.strip().lower():
        if char.isalnum():
            cleaned.append(char)
        elif char in {"-", "_", "."}:
            cleaned.append(char)
        else:
            cleaned.append("-")

    slug = "".join(cleaned)
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-")


def make_public_url(supabase_url: str, bucket: str, object_path: str) -> str:
    return f"{supabase_url}/storage/v1/object/public/{bucket}/{urllib.parse.quote(object_path, safe='/')}"


def make_drop_filename(target: str, version: str) -> str:
    safe_target = slugify(target)
    safe_version = slugify(version)
    prefix = safe_target.capitalize() if safe_target else "Firmware"
    suffix = safe_version or "unknown"
    return f"{prefix}_{suffix}.bin"


def stage_bin_copy(source_path: Path, target: str, version: str) -> Path:
    DROP_DIR.mkdir(parents=True, exist_ok=True)
    destination = DROP_DIR / make_drop_filename(target, version)
    shutil.copy2(source_path, destination)
    return destination


def make_ssl_context() -> ssl.SSLContext:
    insecure_ssl = env_bool("SUPABASE_INSECURE_SSL", False)
    if insecure_ssl:
        print(
            "WARNUNG: TLS-Zertifikatspruefung ist durch SUPABASE_INSECURE_SSL deaktiviert."
        )
        return ssl._create_unverified_context()
    if certifi is not None:
        return ssl.create_default_context(cafile=certifi.where())
    return ssl.create_default_context()


def request_json(method: str,
                 url: str,
                 headers: dict[str, str],
                 data: bytes | None = None,
                 timeout: int = DEFAULT_HTTP_TIMEOUT,
                 retries: int = DEFAULT_HTTP_RETRIES) -> tuple[int, str]:
    request = urllib.request.Request(url=url, data=data, method=method)
    for key, value in headers.items():
        request.add_header(key, value)

    ssl_context = make_ssl_context()

    attempts = max(retries, 1)
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=ssl_context) as response:
                body = response.read().decode("utf-8", errors="replace")
                return response.status, body
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {exc.code} fuer {url}: {body}") from exc
        except TimeoutError as exc:
            last_error = exc
            if attempt == attempts:
                break
            print(f"Timeout beim Request, neuer Versuch {attempt + 1}/{attempts} ...")
        except urllib.error.URLError as exc:
            last_error = exc
            if attempt == attempts:
                break
            print(f"Netzwerkfehler beim Request, neuer Versuch {attempt + 1}/{attempts} ...")

    if isinstance(last_error, urllib.error.URLError):
        raise RuntimeError(f"Netzwerkfehler fuer {url}: {last_error.reason}") from last_error
    if last_error is not None:
        raise RuntimeError(f"Timeout/Verbindungsfehler fuer {url}: {last_error}") from last_error
    raise RuntimeError(f"Unbekannter Fehler fuer {url}")


def upload_file(supabase_url: str,
                service_role_key: str,
                bucket: str,
                object_path: str,
                file_path: Path) -> None:
    encoded_path = urllib.parse.quote(object_path, safe="/")
    url = f"{supabase_url}/storage/v1/object/{bucket}/{encoded_path}"
    data = file_path.read_bytes()
    headers = {
        "apikey": service_role_key,
        "Authorization": f"Bearer {service_role_key}",
        "Content-Type": "application/octet-stream",
        "x-upsert": "true",
    }
    upload_timeout = int(env_value("SUPABASE_UPLOAD_TIMEOUT", str(DEFAULT_UPLOAD_TIMEOUT)) or DEFAULT_UPLOAD_TIMEOUT)
    print(f"Upload-Timeout: {upload_timeout} Sekunden")
    request_json("POST", url, headers, data, timeout=upload_timeout)


def upsert_release(supabase_url: str,
                   service_role_key: str,
                   target: str,
                   version: str,
                   notes: str,
                   storage_path: str,
                   file_size_bytes: int,
                   sha256: str,
                   mandatory: bool,
                   signature_metadata: dict[str, object] | None = None) -> dict[str, object]:
    select_fields = "id,target,version,storage_path,sha256,created_at"
    if signature_metadata:
        select_fields += (
            ",manifest_version,signature_algorithm,signing_key_id,"
            "release_sequence,signature_base64"
        )
    params = urllib.parse.urlencode(
        {
            "on_conflict": "target,version",
            "select": select_fields,
        }
    )
    url = f"{supabase_url}/rest/v1/firmware_releases?{params}"
    release_payload: dict[str, object] = {
        "target": target,
        "version": version,
        "notes": notes,
        "storage_path": storage_path,
        "file_size_bytes": file_size_bytes,
        "sha256": sha256,
        "mandatory": mandatory,
    }
    if signature_metadata:
        release_payload.update(signature_metadata)
    payload = [release_payload]
    headers = {
        "apikey": service_role_key,
        "Authorization": f"Bearer {service_role_key}",
        "Content-Type": "application/json",
        "Prefer": "resolution=merge-duplicates,return=representation",
    }
    _, body = request_json("POST", url, headers, json.dumps(payload).encode("utf-8"))
    rows = json.loads(body)
    if not rows:
        raise RuntimeError("Supabase hat keinen Release-Datensatz zurueckgegeben.")
    return rows[0]


def archive_uploaded_file(source_path: Path, version: str) -> Path:
    timestamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    destination_dir = ARCHIVE_DIR / version
    destination_dir.mkdir(parents=True, exist_ok=True)
    destination_path = destination_dir / f"{timestamp}-{source_path.name}"
    shutil.move(str(source_path), str(destination_path))
    return destination_path


def archive_release_record(
    summary: dict[str, object],
    release: dict[str, object],
    archived_path: Path,
) -> Path:
    record_path = archived_path.with_suffix(archived_path.suffix + ".release.json")
    excluded = {"file_path"}
    record = {
        key: str(value) if isinstance(value, Path) else value
        for key, value in summary.items()
        if key not in excluded
    }
    record["release"] = release
    record["archived_path"] = str(archived_path)
    record_path.write_text(
        json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return record_path


def ensure_setup() -> tuple[str, str, str]:
    DROP_DIR.mkdir(parents=True, exist_ok=True)
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)

    supabase_url = env_value("SUPABASE_URL")
    service_role_key = env_value("SUPABASE_SERVICE_ROLE_KEY")
    bucket = env_value("SUPABASE_STORAGE_BUCKET", "firmware")

    missing = []
    if not supabase_url:
        missing.append("SUPABASE_URL")
    if not service_role_key:
        missing.append("SUPABASE_SERVICE_ROLE_KEY")

    if missing:
        names = ", ".join(missing)
        raise RuntimeError(
            f"Fehlende Konfiguration in env: {names}. "
            f"Bitte .env.example nach env kopieren und ausfuellen."
        )

    return supabase_url.rstrip("/"), service_role_key, bucket.strip()


def build_release_summary(
    supabase_url: str,
    bucket: str,
    file_path: Path,
    target: str,
    version: str,
    notes: str,
    mandatory: bool,
    release_sequence: int | None = None,
) -> dict[str, object]:
    file_size = file_path.stat().st_size
    safe_target = slugify(target)
    safe_version = slugify(version)
    object_path = f"{safe_target}/{safe_version}/{file_path.name}"
    storage_path = f"{bucket}/{object_path}"
    public_url = make_public_url(supabase_url, bucket, object_path)
    sha256 = sha256_of_file(file_path)
    return {
        "file_path": file_path,
        "file_name": file_path.name,
        "target": target,
        "version": version,
        "notes": notes,
        "mandatory": mandatory,
        "release_sequence": release_sequence,
        "file_size": file_size,
        "sha256": sha256,
        "object_path": object_path,
        "storage_path": storage_path,
        "public_url": public_url,
    }


def prepare_release(
    file_path: Path,
    target: str,
    version: str,
    notes: str,
    mandatory: bool,
    release_sequence: int | None = None,
    artifact_origin: str = "existing",
) -> dict[str, object]:
    supabase_url, _service_role_key, bucket = ensure_setup()
    summary = build_release_summary(
        supabase_url=supabase_url,
        bucket=bucket,
        file_path=file_path,
        target=target,
        version=version,
        notes=notes,
        mandatory=mandatory,
        release_sequence=release_sequence,
    )

    mode = signing_mode()
    summary["signing_mode"] = mode
    summary["artifact_origin"] = artifact_origin
    summary["signed"] = False

    if mode == SIGNING_MODE_DISABLED:
        return summary

    if artifact_origin != "build" and not env_bool("OTA_ALLOW_EXISTING_SIGNED_BIN", False):
        raise RuntimeError(
            "Signierte Produktionsreleases duerfen nur aus einem frischen Publisher-Build "
            "stammen. Fuer einen bewusst kontrollierten Ausnahmefall muss "
            "OTA_ALLOW_EXISTING_SIGNED_BIN=1 gesetzt werden."
        )
    if release_sequence is None:
        raise RuntimeError(
            "Fuer ein signiertes Release fehlt die monotone Release-Sequenz."
        )

    try:
        config = signing_config_from_values(env_value)
        manifest = ReleaseManifest(
            target=target,
            version=version,
            release_sequence=release_sequence,
            file_size_bytes=int(summary["file_size"]),
            sha256=str(summary["sha256"]),
            signing_key_id=config.key_id,
        )
        signed_manifest = sign_manifest(manifest, config)
        fingerprint = public_key_fingerprint(config.public_key_path)
        if not config.key_id.endswith(fingerprint[:16]):
            raise SigningError(
                "Die Key-ID passt nicht zum Fingerprint des oeffentlichen Schluessels."
            )
    except SigningError as exc:
        raise RuntimeError(f"Firmware-Signatur fehlgeschlagen: {exc}") from exc

    summary.update(signed_manifest.to_dict())
    summary["public_key_fingerprint"] = fingerprint
    summary["signed"] = True
    return summary


def _assert_prepared_artifact_unchanged(summary: dict[str, object]) -> Path:
    file_path = Path(summary["file_path"])
    if not file_path.is_file():
        raise RuntimeError(f"Vorbereitetes Firmware-Artefakt fehlt: {file_path}")
    current_size = file_path.stat().st_size
    current_sha256 = sha256_of_file(file_path)
    if current_size != int(summary["file_size"]) or current_sha256 != str(summary["sha256"]):
        raise RuntimeError(
            "Das Firmware-Artefakt wurde nach der Vorbereitung veraendert. "
            "Upload aus Sicherheitsgruenden abgebrochen."
        )
    return file_path


def _verify_prepared_signature(summary: dict[str, object]) -> None:
    if not bool(summary.get("signed")):
        if signing_mode() == SIGNING_MODE_REQUIRED:
            raise RuntimeError(
                "Signatur-Pflichtmodus ist aktiv, aber das vorbereitete Release ist unsigniert."
            )
        return

    try:
        config = signing_config_from_values(env_value)
        manifest = ReleaseManifest(
            target=str(summary["target"]),
            version=str(summary["version"]),
            release_sequence=int(summary["release_sequence"]),
            file_size_bytes=int(summary["file_size"]),
            sha256=str(summary["sha256"]),
            signing_key_id=str(summary["signing_key_id"]),
            manifest_version=int(summary["manifest_version"]),
            signature_algorithm=str(summary["signature_algorithm"]),
        )
        if config.key_id != manifest.signing_key_id:
            raise SigningError(
                "Vorbereitetes Release und aktive Signaturkonfiguration verwenden verschiedene Key-IDs."
            )
        fingerprint = public_key_fingerprint(config.public_key_path)
        if not config.key_id.endswith(fingerprint[:16]):
            raise SigningError(
                "Die aktive Key-ID passt nicht zum Fingerprint des oeffentlichen Schluessels."
            )
        if str(summary.get("public_key_fingerprint", "")) != fingerprint:
            raise SigningError(
                "Der oeffentliche Schluessel wurde seit der Release-Vorbereitung geaendert."
            )
        verify_manifest(
            SignedReleaseManifest(
                manifest=manifest,
                signature_base64=str(summary["signature_base64"]),
            ),
            config.public_key_path,
        )
    except (KeyError, TypeError, ValueError, SigningError) as exc:
        raise RuntimeError(
            f"Vorbereitete Firmware-Signatur ist ungueltig: {exc}"
        ) from exc


def _assert_release_row_matches(
    summary: dict[str, object],
    release: dict[str, object],
) -> None:
    expected: dict[str, object] = {
        "target": str(summary["target"]),
        "version": str(summary["version"]),
        "storage_path": str(summary["storage_path"]),
        "sha256": str(summary["sha256"]),
    }
    if bool(summary.get("signed")):
        expected.update(
            {
                "manifest_version": int(summary["manifest_version"]),
                "signature_algorithm": str(summary["signature_algorithm"]),
                "signing_key_id": str(summary["signing_key_id"]),
                "release_sequence": int(summary["release_sequence"]),
                "signature_base64": str(summary["signature_base64"]),
            }
        )
    mismatches = [
        field
        for field, value in expected.items()
        if release.get(field) != value
    ]
    if mismatches:
        raise RuntimeError(
            "Supabase hat abweichende Release-Daten zurueckgegeben: "
            + ", ".join(mismatches)
        )


def publish_prepared_release(summary: dict[str, object]) -> dict[str, object]:
    supabase_url, service_role_key, bucket = ensure_setup()
    file_path = _assert_prepared_artifact_unchanged(summary)
    _verify_prepared_signature(summary)
    if str(summary["object_path"]).split("/", 1)[0] != slugify(str(summary["target"])):
        raise RuntimeError("Vorbereiteter Storage-Pfad passt nicht zum Firmware-Target.")

    signature_metadata: dict[str, object] | None = None
    if bool(summary.get("signed")):
        signature_metadata = {
            "manifest_version": int(summary["manifest_version"]),
            "signature_algorithm": str(summary["signature_algorithm"]),
            "signing_key_id": str(summary["signing_key_id"]),
            "release_sequence": int(summary["release_sequence"]),
            "signature_base64": str(summary["signature_base64"]),
        }

    upload_file(supabase_url, service_role_key, bucket, str(summary["object_path"]), file_path)
    release = upsert_release(
        supabase_url=supabase_url,
        service_role_key=service_role_key,
        target=str(summary["target"]),
        version=str(summary["version"]),
        notes=str(summary["notes"]),
        storage_path=str(summary["storage_path"]),
        file_size_bytes=int(summary["file_size"]),
        sha256=str(summary["sha256"]),
        mandatory=bool(summary["mandatory"]),
        signature_metadata=signature_metadata,
    )
    _assert_release_row_matches(summary, release)
    archived_path = archive_uploaded_file(file_path, slugify(str(summary["version"])))
    release_record_path = archive_release_record(summary, release, archived_path)
    summary["release"] = release
    summary["archived_path"] = archived_path
    summary["release_record_path"] = release_record_path
    return summary


def publish_release(
    file_path: Path,
    target: str,
    version: str,
    notes: str,
    mandatory: bool,
    release_sequence: int | None = None,
    artifact_origin: str = "existing",
) -> dict[str, object]:
    summary = prepare_release(
        file_path=file_path,
        target=target,
        version=version,
        notes=notes,
        mandatory=mandatory,
        release_sequence=release_sequence,
        artifact_origin=artifact_origin,
    )
    return publish_prepared_release(summary)


def main() -> int:
    print("CampClimate OTA Publisher")
    print("-------------------------")

    try:
        supabase_url, service_role_key, bucket = ensure_setup()
    except RuntimeError as exc:
        print(f"Fehler: {exc}")
        return 1

    bin_files = discover_bin_files()
    if not bin_files:
        print(f"Keine .bin im Ordner gefunden: {DROP_DIR}")
        return 1

    file_path = choose_file(bin_files)
    inferred_target = infer_target(file_path.name)
    inferred_version = infer_version(file_path.name)

    target = prompt("Target", inferred_target)
    while not target:
        print("Target darf nicht leer sein.")
        target = prompt("Target", inferred_target)

    version = prompt("Version", inferred_version)
    while not version:
        print("Version darf nicht leer sein.")
        version = prompt("Version", inferred_version)

    notes = prompt("Bezeichnung / Notes", f"{target} {version}")
    mandatory = prompt_bool("Mandatory Update", False)

    release_sequence: int | None = None
    try:
        mode = signing_mode()
    except RuntimeError as exc:
        print(f"Fehler: {exc}")
        return 1
    if mode == SIGNING_MODE_REQUIRED:
        sequence_default = default_release_sequence(target)
        while release_sequence is None:
            sequence_text = prompt("Release-Sequenz", sequence_default)
            try:
                release_sequence = int(sequence_text)
            except ValueError:
                print("Release-Sequenz muss eine ganze Zahl sein.")
                continue
            if release_sequence < 1:
                print("Release-Sequenz muss groesser oder gleich 1 sein.")
                release_sequence = None

    try:
        summary = prepare_release(
            file_path=file_path,
            target=target,
            version=version,
            notes=notes,
            mandatory=mandatory,
            release_sequence=release_sequence,
            artifact_origin="existing",
        )
    except RuntimeError as exc:
        print(f"Fehler: {exc}")
        return 1

    print()
    print("Zusammenfassung")
    print(f"  Datei:        {summary['file_name']}")
    print(f"  Target:       {summary['target']}")
    print(f"  Version:      {summary['version']}")
    print(f"  Notes:        {summary['notes']}")
    print(f"  Mandatory:    {summary['mandatory']}")
    print(f"  Dateigroesse: {summary['file_size']} Bytes")
    print(f"  SHA256:       {summary['sha256']}")
    print(f"  Storage-Pfad: {summary['storage_path']}")
    print(f"  Public URL:   {summary['public_url']}")
    if summary["signed"]:
        print(f"  Signiert:     ja ({summary['signature_algorithm']})")
        print(f"  Key-ID:       {summary['signing_key_id']}")
        print(f"  Sequenz:      {summary['release_sequence']}")
        print(f"  Key-Fingerprint: {summary['public_key_fingerprint']}")
    else:
        print("  Signiert:     NEIN - Legacy-/Vorbereitungsmodus")
    print()

    if not prompt_bool("Jetzt veroeffentlichen", True):
        print("Abgebrochen.")
        return 0

    try:
        print("Upload nach Supabase Storage...")
        result = publish_prepared_release(summary)
    except RuntimeError as exc:
        print(f"Fehler: {exc}")
        return 1

    print()
    print("Fertig.")
    print(f"  Release-ID:   {result['release'].get('id', '')}")
    print(f"  Storage-Pfad: {result['storage_path']}")
    print(f"  Public URL:   {result['public_url']}")
    print(f"  Archiviert:   {result['archived_path']}")
    print(f"  Release-Akte: {result['release_record_path']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
