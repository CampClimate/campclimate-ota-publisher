#!/usr/bin/env python3

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import ssl
import struct
import subprocess
import sys
import tempfile
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
RELEASE_SEQUENCE_MARKER = b"CCFWSEQ1"
RELEASE_SEQUENCE_BYTES = 8
CENTRAL_PROJECT_ROOT = ROOT.parent / "CampClimate Central 2.0"
CENTRAL_IMAGE_TOOL = CENTRAL_PROJECT_ROOT / "tools" / "security" / "image_tool.py"
CENTRAL_SECURE_BOOT_PRIVATE_KEY_ENV = "CENTRAL_SECURE_BOOT_PRIVATE_KEY"
CENTRAL_EXPECTED_IMAGE_KIND = "production"
CENTRAL_EXPECTED_HARDWARE = "2.0"
CENTRAL_EXPECTED_SIGNATURE_SCHEME = "rsa3072"
RELEASE_SELECT_FIELDS = (
    "id,target,version,notes,storage_path,file_size_bytes,sha256,mandatory,"
    "published,manifest_version,signature_algorithm,signing_key_id,"
    "release_sequence,signature_base64,created_at"
)


class HttpRequestError(RuntimeError):
    def __init__(self, status: int, url: str, body: str) -> None:
        self.status = status
        self.url = url
        self.body = body
        super().__init__(f"HTTP {status} fuer {url}: {body}")


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
    if lowered.startswith("outdoor_"):
        return "outdoor"
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


def embedded_release_sequence(path: Path) -> int:
    data = path.read_bytes()
    offsets: list[int] = []
    start = 0
    while True:
        offset = data.find(RELEASE_SEQUENCE_MARKER, start)
        if offset < 0:
            break
        offsets.append(offset)
        start = offset + 1

    if len(offsets) != 1:
        raise RuntimeError(
            "Das Firmware-BIN muss genau eine CampClimate-Release-Sequenzmarke "
            f"enthalten; gefunden: {len(offsets)}."
        )

    value_offset = offsets[0] + len(RELEASE_SEQUENCE_MARKER)
    value_end = value_offset + RELEASE_SEQUENCE_BYTES
    if value_end > len(data):
        raise RuntimeError("Die eingebettete Release-Sequenz im Firmware-BIN ist unvollstaendig.")
    return struct.unpack_from("<Q", data, value_offset)[0]


def assert_embedded_release_sequence(path: Path, expected_sequence: int) -> int:
    actual_sequence = embedded_release_sequence(path)
    if actual_sequence != expected_sequence:
        raise RuntimeError(
            "Die eingebettete Release-Sequenz des Firmware-BIN passt nicht zur "
            f"Publisher-Eingabe: BIN={actual_sequence}, Eingabe={expected_sequence}."
        )
    return actual_sequence


def _path_is_inside_git_repository(path: Path) -> bool:
    for parent in (path.parent, *path.parents):
        if (parent / ".git").exists():
            return True
    return False


def _central_secure_boot_private_key() -> Path:
    configured = env_value(CENTRAL_SECURE_BOOT_PRIVATE_KEY_ENV, "").strip()
    if not configured:
        raise RuntimeError(
            "Central-Publish abgebrochen: "
            f"{CENTRAL_SECURE_BOOT_PRIVATE_KEY_ENV} ist nicht gesetzt."
        )
    key_path = Path(configured)
    if not key_path.is_absolute():
        raise RuntimeError(
            "Der Central-Secure-Boot-Schluessel muss als absoluter Pfad "
            "konfiguriert werden."
        )
    try:
        resolved = key_path.resolve(strict=True)
    except OSError:
        raise RuntimeError(
            "Der konfigurierte Central-Secure-Boot-Schluessel ist nicht lesbar."
        ) from None
    if not resolved.is_file():
        raise RuntimeError(
            "Der konfigurierte Central-Secure-Boot-Schluessel ist keine regulaere Datei."
        )
    if _path_is_inside_git_repository(resolved):
        raise RuntimeError(
            "Der Central-Secure-Boot-Schluessel darf nicht in einem Git-Repository liegen."
        )
    try:
        key_permissions = resolved.stat().st_mode & 0o777
    except OSError:
        raise RuntimeError(
            "Der konfigurierte Central-Secure-Boot-Schluessel ist nicht lesbar."
        ) from None
    if key_permissions != 0o600:
        raise RuntimeError(
            "Der Central-Secure-Boot-Schluessel darf nur fuer den aktuellen "
            "Benutzer lesbar sein (Dateimodus 0600)."
        )
    return resolved


def _run_central_image_tool(arguments: list[str]) -> dict[str, object]:
    if not CENTRAL_IMAGE_TOOL.is_file():
        raise RuntimeError(
            "Central-Publish abgebrochen: Das verbindliche image_tool.py fehlt."
        )
    try:
        completed = subprocess.run(
            [sys.executable, str(CENTRAL_IMAGE_TOOL), *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError(
            "Central-Secure-Boot-Pruefung konnte nicht ausgefuehrt werden."
        ) from None
    if completed.returncode != 0:
        # stderr can contain the private key path. Deliberately do not include it.
        raise RuntimeError(
            "Central-Secure-Boot-Pruefung oder -Signierung wurde abgelehnt."
        )
    try:
        result = json.loads(completed.stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            "Central image_tool.py hat kein gueltiges Pruefergebnis geliefert."
        ) from exc
    if not isinstance(result, dict):
        raise RuntimeError(
            "Central image_tool.py hat kein gueltiges Pruefergebnis geliefert."
        )
    return result


def _assert_central_image_identity(
    info: dict[str, object],
    expected_sequence: int,
    *,
    require_verified_signature: bool,
) -> None:
    expected: dict[str, object] = {
        "image_kind": CENTRAL_EXPECTED_IMAGE_KIND,
        "hardware": CENTRAL_EXPECTED_HARDWARE,
        "release_sequence": expected_sequence,
        "policy_version": 1,
    }
    mismatches = [name for name, value in expected.items() if info.get(name) != value]
    if mismatches:
        raise RuntimeError(
            "Central-ImageIdentity passt nicht zum Produktionsrelease: "
            + ", ".join(mismatches)
            + "."
        )
    generation = info.get("security_generation")
    if not isinstance(generation, int) or not 0 <= generation <= 16:
        raise RuntimeError("Central-ImageIdentity enthaelt keine gueltige Security-Generation.")
    if require_verified_signature:
        if (
            info.get("signature_present") is not True
            or info.get("signature_verified") is not True
            or info.get("signature_scheme") != CENTRAL_EXPECTED_SIGNATURE_SCHEME
        ):
            raise RuntimeError(
                "Central-Produktionsimage besitzt keine verifizierte RSA-3072-"
                "Secure-Boot-V2-Signatur."
            )


def _new_private_central_artifact_path(version: str) -> tuple[Path, Path]:
    DROP_DIR.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix=".central-sbv2-", dir=DROP_DIR))
    directory.chmod(0o700)
    output = directory / make_drop_filename("central", version)
    if output.exists():
        raise RuntimeError("Privater Central-Stagingpfad ist unerwartet bereits belegt.")
    return directory, output


def _copy_private_without_clobber(source: Path, destination: Path) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(destination, flags, 0o600)
    try:
        with source.open("rb") as input_handle, os.fdopen(
            descriptor, "wb", closefd=False
        ) as output_handle:
            shutil.copyfileobj(input_handle, output_handle, length=65536)
            output_handle.flush()
            os.fsync(output_handle.fileno())
    except Exception:
        try:
            destination.unlink()
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(descriptor)


def _remove_private_central_artifact(directory: Path, artifact: Path) -> None:
    try:
        artifact.unlink()
    except FileNotFoundError:
        pass
    try:
        directory.rmdir()
    except OSError:
        pass


def _central_staging_paths(
    summary: dict[str, object],
) -> tuple[Path, Path] | None:
    raw_directory = summary.get("_central_private_staging_dir")
    raw_artifact = summary.get("file_path")
    if raw_directory is None or raw_artifact is None:
        return None
    directory = Path(raw_directory)
    artifact = Path(raw_artifact)
    try:
        drop_directory = DROP_DIR.resolve()
        resolved_directory = directory.resolve(strict=False)
        resolved_artifact = artifact.resolve(strict=False)
    except OSError:
        return None
    if (
        resolved_directory.parent != drop_directory
        or not resolved_directory.name.startswith(".central-sbv2-")
        or resolved_artifact.parent != resolved_directory
    ):
        return None
    return resolved_directory, resolved_artifact


def cleanup_prepared_release(summary: dict[str, object]) -> None:
    """Remove only Publisher-owned private Central staging files."""
    paths = _central_staging_paths(summary)
    if paths is None:
        return
    directory, artifact = paths
    _remove_private_central_artifact(directory, artifact)
    summary.pop("_central_private_staging_dir", None)


def _prepare_central_secure_boot_artifact(
    source: Path,
    version: str,
    release_sequence: int,
    artifact_origin: str,
) -> tuple[Path, dict[str, object], Path]:
    if not source.is_file():
        raise RuntimeError(f"Central-Build-Artefakt fehlt: {source}")
    key_path = _central_secure_boot_private_key()
    inspected = _run_central_image_tool([str(source)])
    _assert_central_image_identity(
        inspected,
        release_sequence,
        require_verified_signature=False,
    )

    signature_present = inspected.get("signature_present") is True
    if artifact_origin == "build" and signature_present:
        raise RuntimeError(
            "Ein frischer Central-Build muss unsigniert an den Publisher uebergeben "
            "werden; das Artefakt war bereits signiert."
        )
    if artifact_origin != "build" and not env_bool(
        "OTA_ALLOW_EXISTING_SIGNED_BIN", False
    ):
        raise RuntimeError(
            "Central-Produktionsreleases duerfen nur aus einem frischen Publisher-Build "
            "stammen. Ein vorhandenes, bereits signiertes BIN erfordert den bewusst "
            "kontrollierten Ausnahmefall OTA_ALLOW_EXISTING_SIGNED_BIN=1."
        )
    if artifact_origin != "build" and not signature_present:
        raise RuntimeError(
            "Der Ausnahmeweg akzeptiert nur ein bereits RSA-3072-signiertes Central-BIN; "
            "beliebige vorhandene BIN-Dateien werden nicht nachsigniert."
        )

    directory, signed_output = _new_private_central_artifact_path(version)
    try:
        if artifact_origin == "build":
            signed_info = _run_central_image_tool(
                [
                    str(source),
                    "--sign-key",
                    str(key_path),
                    "--output",
                    str(signed_output),
                    "--audience",
                    "customer",
                ]
            )
        else:
            verified_source = _run_central_image_tool(
                [str(source), "--verify-key", str(key_path)]
            )
            _assert_central_image_identity(
                verified_source,
                release_sequence,
                require_verified_signature=True,
            )
            _copy_private_without_clobber(source, signed_output)
            signed_info = _run_central_image_tool(
                [str(signed_output), "--verify-key", str(key_path)]
            )

        _assert_central_image_identity(
            signed_info,
            release_sequence,
            require_verified_signature=True,
        )
        if (signed_output.stat().st_mode & 0o777) != 0o600:
            raise RuntimeError("Central-Secure-Boot-Artefakt besitzt nicht Modus 0600.")
        return signed_output, signed_info, directory
    except Exception:
        _remove_private_central_artifact(directory, signed_output)
        raise


def _verify_prepared_central_secure_boot(
    summary: dict[str, object],
    file_path: Path,
) -> None:
    if str(summary.get("target", "")) != "central":
        return
    if summary.get("central_secure_boot_verified") is not True:
        raise RuntimeError(
            "Central-Publish abgebrochen: verifizierte Secure-Boot-Signierung fehlt."
        )
    try:
        expected_sequence = int(summary["release_sequence"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError(
            "Central-Publish abgebrochen: Release-Sequenz fehlt."
        ) from exc
    key_path = _central_secure_boot_private_key()
    verified = _run_central_image_tool(
        [str(file_path), "--verify-key", str(key_path)]
    )
    _assert_central_image_identity(
        verified,
        expected_sequence,
        require_verified_signature=True,
    )
    for field in (
        "image_kind",
        "hardware",
        "release_sequence",
        "security_generation",
        "policy_version",
        "signature_scheme",
    ):
        if summary.get(f"central_{field}") != verified.get(field):
            raise RuntimeError(
                "Central-Secure-Boot-Metadaten wurden nach der Vorbereitung veraendert."
            )


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


def request_bytes(method: str,
                  url: str,
                  headers: dict[str, str],
                  data: bytes | None = None,
                  timeout: int = DEFAULT_HTTP_TIMEOUT,
                  retries: int = DEFAULT_HTTP_RETRIES) -> tuple[int, bytes]:
    request = urllib.request.Request(url=url, data=data, method=method)
    for key, value in headers.items():
        request.add_header(key, value)

    ssl_context = make_ssl_context()

    attempts = max(retries, 1)
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=ssl_context) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise HttpRequestError(exc.code, url, body) from exc
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


def request_json(method: str,
                 url: str,
                 headers: dict[str, str],
                 data: bytes | None = None,
                 timeout: int = DEFAULT_HTTP_TIMEOUT,
                 retries: int = DEFAULT_HTTP_RETRIES) -> tuple[int, str]:
    status, body = request_bytes(
        method,
        url,
        headers,
        data,
        timeout=timeout,
        retries=retries,
    )
    return status, body.decode("utf-8", errors="replace")


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
        "x-upsert": "false",
    }
    upload_timeout = int(env_value("SUPABASE_UPLOAD_TIMEOUT", str(DEFAULT_UPLOAD_TIMEOUT)) or DEFAULT_UPLOAD_TIMEOUT)
    print(f"Upload-Timeout: {upload_timeout} Sekunden")
    request_json("POST", url, headers, data, timeout=upload_timeout)


def download_public_object(supabase_url: str,
                           service_role_key: str,
                           bucket: str,
                           object_path: str) -> bytes:
    url = make_public_url(supabase_url, bucket, object_path)
    headers = {
        "apikey": service_role_key,
        "Authorization": f"Bearer {service_role_key}",
        "Cache-Control": "no-cache",
    }
    _, body = request_bytes("GET", url, headers)
    return body


def verify_remote_artifact(supabase_url: str,
                           service_role_key: str,
                           bucket: str,
                           object_path: str,
                           expected_size: int,
                           expected_sha256: str) -> None:
    body = download_public_object(
        supabase_url,
        service_role_key,
        bucket,
        object_path,
    )
    actual_sha256 = hashlib.sha256(body).hexdigest()
    if len(body) != expected_size or actual_sha256 != expected_sha256:
        raise RuntimeError(
            "Supabase-Readback stimmt nicht mit dem lokalen Firmware-Artefakt "
            "ueberein."
        )


def upload_immutable_artifact(supabase_url: str,
                              service_role_key: str,
                              bucket: str,
                              object_path: str,
                              file_path: Path,
                              expected_size: int,
                              expected_sha256: str) -> None:
    try:
        upload_file(
            supabase_url,
            service_role_key,
            bucket,
            object_path,
            file_path,
        )
    except HttpRequestError as exc:
        normalized_body = exc.body.lower()
        duplicate = exc.status in {400, 409} and (
            "duplicate" in normalized_body
            or "already exists" in normalized_body
            or "resource already exists" in normalized_body
        )
        if not duplicate:
            raise
        print("Content-addressed Storage-Objekt existiert bereits; Readback wird geprueft.")

    verify_remote_artifact(
        supabase_url,
        service_role_key,
        bucket,
        object_path,
        expected_size,
        expected_sha256,
    )


def _service_headers(service_role_key: str) -> dict[str, str]:
    return {
        "apikey": service_role_key,
        "Authorization": f"Bearer {service_role_key}",
    }


def _decode_release_rows(body: str) -> list[dict[str, object]]:
    rows = json.loads(body)
    if not isinstance(rows, list):
        raise RuntimeError("Supabase hat keine Release-Liste zurueckgegeben.")
    return rows


def fetch_release_by_target_version(supabase_url: str,
                                    service_role_key: str,
                                    target: str,
                                    version: str) -> dict[str, object] | None:
    params = urllib.parse.urlencode(
        {
            "select": RELEASE_SELECT_FIELDS,
            "target": f"eq.{target}",
            "version": f"eq.{version}",
            "limit": "2",
        }
    )
    url = f"{supabase_url}/rest/v1/firmware_releases?{params}"
    _, body = request_json("GET", url, _service_headers(service_role_key))
    rows = _decode_release_rows(body)
    if len(rows) > 1:
        raise RuntimeError(
            "Supabase enthaelt mehrere Releases fuer dieselbe Target-/Versionskombination."
        )
    return rows[0] if rows else None


def fetch_release_by_id(supabase_url: str,
                        service_role_key: str,
                        release_id: str) -> dict[str, object]:
    params = urllib.parse.urlencode(
        {
            "select": RELEASE_SELECT_FIELDS,
            "id": f"eq.{release_id}",
            "limit": "2",
        }
    )
    url = f"{supabase_url}/rest/v1/firmware_releases?{params}"
    _, body = request_json("GET", url, _service_headers(service_role_key))
    rows = _decode_release_rows(body)
    if len(rows) != 1:
        raise RuntimeError(
            "Supabase-Readback hat nicht exakt einen Release-Datensatz geliefert."
        )
    return rows[0]


def fetch_latest_signed_release(supabase_url: str,
                                service_role_key: str,
                                target: str) -> dict[str, object] | None:
    params = urllib.parse.urlencode(
        {
            "select": "id,version,release_sequence,published",
            "target": f"eq.{target}",
            "release_sequence": "not.is.null",
            "order": "release_sequence.desc",
            "limit": "1",
        }
    )
    url = f"{supabase_url}/rest/v1/firmware_releases?{params}"
    _, body = request_json("GET", url, _service_headers(service_role_key))
    rows = _decode_release_rows(body)
    return rows[0] if rows else None


def insert_unpublished_release(
    supabase_url: str,
    service_role_key: str,
    summary: dict[str, object],
) -> dict[str, object]:
    params = urllib.parse.urlencode({"select": RELEASE_SELECT_FIELDS})
    url = f"{supabase_url}/rest/v1/firmware_releases?{params}"
    release_payload: dict[str, object] = {
        "target": str(summary["target"]),
        "version": str(summary["version"]),
        "notes": str(summary["notes"]),
        "storage_path": str(summary["storage_path"]),
        "file_size_bytes": int(summary["file_size"]),
        "sha256": str(summary["sha256"]),
        "mandatory": bool(summary["mandatory"]),
        "published": False,
    }
    if bool(summary.get("signed")):
        release_payload.update(
            {
                "manifest_version": int(summary["manifest_version"]),
                "signature_algorithm": str(summary["signature_algorithm"]),
                "signing_key_id": str(summary["signing_key_id"]),
                "release_sequence": int(summary["release_sequence"]),
                "signature_base64": str(summary["signature_base64"]),
            }
        )
    payload = [release_payload]
    headers = {
        **_service_headers(service_role_key),
        "Content-Type": "application/json",
        "Prefer": "return=representation",
    }
    _, body = request_json(
        "POST",
        url,
        headers,
        json.dumps(payload).encode("utf-8"),
        retries=1,
    )
    rows = _decode_release_rows(body)
    if len(rows) != 1:
        raise RuntimeError(
            "Supabase hat nach dem Insert nicht exakt einen Release-Datensatz zurueckgegeben."
        )
    return rows[0]


def mark_release_published(supabase_url: str,
                           service_role_key: str,
                           release_id: str) -> dict[str, object]:
    params = urllib.parse.urlencode(
        {
            "id": f"eq.{release_id}",
            "published": "eq.false",
            "select": RELEASE_SELECT_FIELDS,
        }
    )
    url = f"{supabase_url}/rest/v1/firmware_releases?{params}"
    headers = {
        **_service_headers(service_role_key),
        "Content-Type": "application/json",
        "Prefer": "return=representation",
    }
    _, body = request_json(
        "PATCH",
        url,
        headers,
        json.dumps({"published": True}).encode("utf-8"),
        retries=1,
    )
    rows = _decode_release_rows(body)
    if len(rows) != 1:
        raise RuntimeError(
            "Release konnte nicht kontrolliert von unpublished auf published gesetzt werden."
        )
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
        if key not in excluded and not key.startswith("_")
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
    normalized_target = target.strip().lower()
    if normalized_target not in {"basic", "central", "outdoor"}:
        raise RuntimeError("Target muss 'basic', 'central' oder 'outdoor' sein.")
    normalized_version = version.strip()
    if not normalized_version:
        raise RuntimeError("Version darf nicht leer sein.")

    file_size = file_path.stat().st_size
    sha256 = sha256_of_file(file_path)
    object_path = f"{normalized_target}/sha256/{sha256}.bin"
    storage_path = f"{bucket}/{object_path}"
    public_url = make_public_url(supabase_url, bucket, object_path)
    return {
        "file_path": file_path,
        "file_name": file_path.name,
        "target": normalized_target,
        "version": normalized_version,
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
    normalized_target = target.strip().lower()
    if normalized_target not in {"basic", "central", "outdoor"}:
        raise RuntimeError("Target muss 'basic', 'central' oder 'outdoor' sein.")
    if artifact_origin not in {"build", "existing"}:
        raise RuntimeError("Artefakt-Ursprung muss 'build' oder 'existing' sein.")
    mode = signing_mode()
    central_staging_directory: Path | None = None
    prepared_file_path = file_path
    central_info: dict[str, object] | None = None

    if normalized_target == "central":
        if (
            not isinstance(release_sequence, int)
            or isinstance(release_sequence, bool)
            or not 1 <= release_sequence <= 0xFFFFFFFFFFFFFFFF
        ):
            raise RuntimeError(
                "Fuer jedes Central-Produktionsimage ist eine Release-Sequenz "
                "groesser oder gleich 1 Pflicht."
            )
        prepared_file_path, central_info, central_staging_directory = (
            _prepare_central_secure_boot_artifact(
                file_path,
                version,
                release_sequence,
                artifact_origin,
            )
        )

    try:
        summary = build_release_summary(
            supabase_url=supabase_url,
            bucket=bucket,
            file_path=prepared_file_path,
            target=normalized_target,
            version=version,
            notes=notes,
            mandatory=mandatory,
            release_sequence=release_sequence,
        )
        summary["signing_mode"] = mode
        summary["artifact_origin"] = artifact_origin
        summary["signed"] = False

        if central_info is not None and central_staging_directory is not None:
            summary["_central_private_staging_dir"] = central_staging_directory
            summary["central_secure_boot_verified"] = True
            for field in (
                "image_kind",
                "hardware",
                "release_sequence",
                "security_generation",
                "policy_version",
                "signature_scheme",
            ):
                summary[f"central_{field}"] = central_info[field]
            # Central's fixed descriptor is verified by image_tool against the
            # signed image. The old CCFWSEQ1 marker may be removed by the linker
            # now that the Central runtime reads its sequence from that descriptor.
            summary["embedded_release_sequence"] = central_info["release_sequence"]

        if mode == SIGNING_MODE_DISABLED:
            return summary

        if (
            normalized_target in {"basic", "outdoor"}
            and artifact_origin != "build"
            and not env_bool("OTA_ALLOW_EXISTING_SIGNED_BIN", False)
        ):
            raise RuntimeError(
                "Signierte Produktionsreleases duerfen nur aus einem frischen Publisher-Build "
                "stammen. Fuer einen bewusst kontrollierten Ausnahmefall muss "
                "OTA_ALLOW_EXISTING_SIGNED_BIN=1 gesetzt werden."
            )
        if release_sequence is None:
            raise RuntimeError(
                "Fuer ein signiertes Release fehlt die monotone Release-Sequenz."
            )
        if normalized_target in {"basic", "outdoor"}:
            summary["embedded_release_sequence"] = assert_embedded_release_sequence(
                prepared_file_path,
                release_sequence,
            )

        config = signing_config_from_values(env_value)
        manifest = ReleaseManifest(
            target=str(summary["target"]),
            version=str(summary["version"]),
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
        summary.update(signed_manifest.to_dict())
        summary["public_key_fingerprint"] = fingerprint
        summary["signed"] = True
        return summary
    except SigningError as exc:
        if central_staging_directory is not None:
            _remove_private_central_artifact(
                central_staging_directory,
                prepared_file_path,
            )
        raise RuntimeError(f"Firmware-Signatur fehlgeschlagen: {exc}") from exc
    except Exception:
        if central_staging_directory is not None:
            _remove_private_central_artifact(
                central_staging_directory,
                prepared_file_path,
            )
        raise


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
    *,
    expected_published: bool | None = None,
) -> None:
    expected: dict[str, object] = {
        "target": str(summary["target"]),
        "version": str(summary["version"]),
        "notes": str(summary["notes"]),
        "storage_path": str(summary["storage_path"]),
        "file_size_bytes": int(summary["file_size"]),
        "sha256": str(summary["sha256"]),
        "mandatory": bool(summary["mandatory"]),
    }
    if expected_published is not None:
        expected["published"] = expected_published
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


def _adopt_existing_release(
    summary: dict[str, object],
    existing: dict[str, object],
) -> None:
    if bool(summary.get("signed")):
        existing_signature = str(existing.get("signature_base64") or "")
        recovered_summary = dict(summary)
        recovered_summary["signature_base64"] = existing_signature
        _verify_prepared_signature(recovered_summary)
        summary["signature_base64"] = existing_signature

    _assert_release_row_matches(
        summary,
        existing,
        expected_published=bool(existing.get("published")),
    )


def _assert_release_sequence_monotonic(
    supabase_url: str,
    service_role_key: str,
    summary: dict[str, object],
    existing: dict[str, object] | None,
) -> None:
    if not bool(summary.get("signed")):
        return

    latest = fetch_latest_signed_release(
        supabase_url,
        service_role_key,
        str(summary["target"]),
    )
    if latest is None:
        return

    candidate = int(summary["release_sequence"])
    latest_sequence = int(latest["release_sequence"])
    recovering_same_row = (
        existing is not None
        and str(existing.get("id", "")) == str(latest.get("id", ""))
        and candidate == latest_sequence
    )
    if not recovering_same_row and candidate <= latest_sequence:
        raise RuntimeError(
            f"Release-Sequenz {candidate} ist nicht groesser als die aktuell "
            f"hoechste Sequenz {latest_sequence} fuer {summary['target']}."
        )


def preflight_release(
    supabase_url: str,
    service_role_key: str,
    summary: dict[str, object],
) -> dict[str, object] | None:
    existing = fetch_release_by_target_version(
        supabase_url,
        service_role_key,
        str(summary["target"]),
        str(summary["version"]),
    )
    if existing is not None:
        _adopt_existing_release(summary, existing)

    _assert_release_sequence_monotonic(
        supabase_url,
        service_role_key,
        summary,
        existing,
    )
    return existing


def publish_prepared_release(summary: dict[str, object]) -> dict[str, object]:
    try:
        supabase_url, service_role_key, bucket = ensure_setup()
        file_path = _assert_prepared_artifact_unchanged(summary)
        _verify_prepared_central_secure_boot(summary, file_path)
        _verify_prepared_signature(summary)
        expected_object_path = (
            f"{summary['target']}/sha256/{summary['sha256']}.bin"
        )
        if str(summary["object_path"]) != expected_object_path:
            raise RuntimeError(
                "Vorbereiteter Storage-Pfad ist nicht content-addressed oder passt "
                "nicht zu Target und SHA256."
            )
        if str(summary["storage_path"]) != f"{bucket}/{expected_object_path}":
            raise RuntimeError("Vorbereiteter Storage-Pfad passt nicht zum aktiven Bucket.")

        existing = preflight_release(supabase_url, service_role_key, summary)
        upload_immutable_artifact(
            supabase_url,
            service_role_key,
            bucket,
            str(summary["object_path"]),
            file_path,
            int(summary["file_size"]),
            str(summary["sha256"]),
        )

        if existing is None:
            release = insert_unpublished_release(
                supabase_url,
                service_role_key,
                summary,
            )
            _assert_release_row_matches(
                summary,
                release,
                expected_published=False,
            )
        else:
            release = existing

        if bool(release.get("published")):
            published_release = release
        else:
            release_id = str(release.get("id", ""))
            if not release_id:
                raise RuntimeError("Supabase-Release besitzt keine gueltige ID.")
            readback_release = fetch_release_by_id(
                supabase_url,
                service_role_key,
                release_id,
            )
            _assert_release_row_matches(
                summary,
                readback_release,
                expected_published=False,
            )
            published_release = mark_release_published(
                supabase_url,
                service_role_key,
                release_id,
            )
            _assert_release_row_matches(
                summary,
                published_release,
                expected_published=True,
            )

        archived_path = archive_uploaded_file(file_path, slugify(str(summary["version"])))
        release_record_path = archive_release_record(
            summary,
            published_release,
            archived_path,
        )
        summary["release"] = published_release
        summary["archived_path"] = archived_path
        summary["release_record_path"] = release_record_path
        return summary
    finally:
        cleanup_prepared_release(summary)


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
    if mode == SIGNING_MODE_REQUIRED or target.strip().lower() == "central":
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
    if summary.get("central_secure_boot_verified") is True:
        print(
            "  Secure Boot:  ja "
            f"({summary['central_signature_scheme']}, "
            f"Security-Generation {summary['central_security_generation']})"
        )
    if summary["signed"]:
        print(f"  Signiert:     ja ({summary['signature_algorithm']})")
        print(f"  Key-ID:       {summary['signing_key_id']}")
        print(f"  Sequenz:      {summary['release_sequence']}")
        print(f"  Key-Fingerprint: {summary['public_key_fingerprint']}")
    else:
        print("  Manifest:     NICHT ECDSA-signiert - Legacy-/Vorbereitungsmodus")
    print()

    if not prompt_bool("Jetzt veroeffentlichen", True):
        cleanup_prepared_release(summary)
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
