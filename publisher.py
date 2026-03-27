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


ROOT = Path(__file__).resolve().parent
DROP_DIR = ROOT / "drop"
ARCHIVE_DIR = ROOT / "archive"
ENV_FILE = ROOT / "env"


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


def request_json(method: str,
                 url: str,
                 headers: dict[str, str],
                 data: bytes | None = None) -> tuple[int, str]:
    request = urllib.request.Request(url=url, data=data, method=method)
    for key, value in headers.items():
        request.add_header(key, value)

    ssl_context = None
    insecure_ssl = env_value("SUPABASE_INSECURE_SSL", "0").strip().lower() in {
        "1", "true", "yes", "y", "on"
    }
    if insecure_ssl:
        ssl_context = ssl._create_unverified_context()

    try:
        with urllib.request.urlopen(request, timeout=30, context=ssl_context) as response:
            body = response.read().decode("utf-8", errors="replace")
            return response.status, body
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code} fuer {url}: {body}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Netzwerkfehler fuer {url}: {exc.reason}") from exc


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
    request_json("POST", url, headers, data)


def upsert_release(supabase_url: str,
                   service_role_key: str,
                   target: str,
                   version: str,
                   notes: str,
                   storage_path: str,
                   file_size_bytes: int,
                   sha256: str,
                   mandatory: bool) -> dict[str, object]:
    params = urllib.parse.urlencode(
        {
            "on_conflict": "target,version",
            "select": "id,target,version,storage_path,sha256,created_at",
        }
    )
    url = f"{supabase_url}/rest/v1/firmware_releases?{params}"
    payload = [
        {
            "target": target,
            "version": version,
            "notes": notes,
            "storage_path": storage_path,
            "file_size_bytes": file_size_bytes,
            "sha256": sha256,
            "mandatory": mandatory,
        }
    ]
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
    file_size = file_path.stat().st_size
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

    safe_target = slugify(target)
    safe_version = slugify(version)
    object_path = f"{safe_target}/{safe_version}/{file_path.name}"
    storage_path = f"{bucket}/{object_path}"
    public_url = f"{supabase_url}/storage/v1/object/public/{bucket}/{urllib.parse.quote(object_path, safe='/')}"
    sha256 = sha256_of_file(file_path)

    print()
    print("Zusammenfassung")
    print(f"  Datei:        {file_path.name}")
    print(f"  Target:       {target}")
    print(f"  Version:      {version}")
    print(f"  Notes:        {notes}")
    print(f"  Mandatory:    {mandatory}")
    print(f"  Dateigroesse: {file_size} Bytes")
    print(f"  SHA256:       {sha256}")
    print(f"  Storage-Pfad: {storage_path}")
    print(f"  Public URL:   {public_url}")
    print()

    if not prompt_bool("Jetzt veroeffentlichen", True):
        print("Abgebrochen.")
        return 0

    try:
        print("Upload nach Supabase Storage...")
        upload_file(supabase_url, service_role_key, bucket, object_path, file_path)

        print("Release in firmware_releases speichern...")
        release = upsert_release(
            supabase_url=supabase_url,
            service_role_key=service_role_key,
            target=target,
            version=version,
            notes=notes,
            storage_path=storage_path,
            file_size_bytes=file_size,
            sha256=sha256,
            mandatory=mandatory,
        )

        archived_path = archive_uploaded_file(file_path, safe_version)
    except RuntimeError as exc:
        print(f"Fehler: {exc}")
        return 1

    print()
    print("Fertig.")
    print(f"  Release-ID:   {release.get('id', '')}")
    print(f"  Storage-Pfad: {storage_path}")
    print(f"  Public URL:   {public_url}")
    print(f"  Archiviert:   {archived_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
