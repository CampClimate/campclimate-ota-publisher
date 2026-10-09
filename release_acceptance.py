"""Strict offline release acceptance receipt validation.

The receipt is a human attestation that the ordered software, TestFW-board,
and vehicle checks were completed for the exact signed firmware artifact.
Validation is deliberately local and fail-closed; it does not authenticate
the approver and does not claim that hardware validation happened
automatically.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
STAGE_NAMES = ("software", "test_firmware", "vehicle")
_SHA256_HEX = frozenset("0123456789abcdef")


class ReleaseAcceptanceError(RuntimeError):
    """Raised when the local release acceptance receipt is invalid."""


def _duplicate_rejector(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseAcceptanceError(f"Doppelter JSON-Schluessel: {key}")
        result[key] = value
    return result


def _object(value: Any, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise ReleaseAcceptanceError(f"{label} muss ein JSON-Objekt sein.")
    return value


def _exact_fields(value: dict[str, Any], expected: set[str], label: str) -> None:
    unknown = sorted(set(value) - expected)
    missing = sorted(expected - set(value))
    if unknown:
        raise ReleaseAcceptanceError(
            f"{label} enthaelt unbekannte Felder: {', '.join(unknown)}."
        )
    if missing:
        raise ReleaseAcceptanceError(
            f"{label} enthaelt fehlende Felder: {', '.join(missing)}."
        )


def _string(value: Any, label: str, *, nonempty: bool = True) -> str:
    if type(value) is not str or (nonempty and not value.strip()):
        raise ReleaseAcceptanceError(f"{label} muss ein nichtleerer String sein.")
    return value


def _positive_int(value: Any, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise ReleaseAcceptanceError(f"{label} muss eine positive Ganzzahl sein.")
    return value


def _strict_bool(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise ReleaseAcceptanceError(f"{label} muss true oder false sein.")
    return value


def _sha256(value: Any, label: str) -> str:
    if type(value) is not str or len(value) != 64 or any(
        char not in _SHA256_HEX for char in value
    ):
        raise ReleaseAcceptanceError(f"{label} muss aus genau 64 Kleinbuchstaben-Hexzeichen bestehen.")
    return value


def _timestamp(value: Any, label: str) -> dt.datetime:
    text = _string(value, label)
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError as exc:
        raise ReleaseAcceptanceError(f"{label} ist kein ISO-8601-Zeitstempel.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ReleaseAcceptanceError(f"{label} muss eine Zeitzone enthalten.")
    return parsed


def _resolve_receipt_path(raw_path: str, root: Path) -> Path:
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = root / path
    try:
        return path.resolve(strict=True)
    except OSError as exc:
        raise ReleaseAcceptanceError(
            f"Release-Akte ist nicht lesbar: {path}"
        ) from exc


def _hash_file(path: Path, label: str) -> str:
    if not path.is_file():
        raise ReleaseAcceptanceError(f"{label} ist keine regulaere Datei: {path}")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
    except OSError as exc:
        raise ReleaseAcceptanceError(f"{label} ist nicht lesbar: {path}") from exc
    return digest.hexdigest()


def _read_json(path: Path) -> tuple[dict[str, Any], str]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ReleaseAcceptanceError(f"Release-Akte ist nicht lesbar: {path}") from exc
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_duplicate_rejector)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseAcceptanceError("Release-Akte ist kein gueltiges UTF-8-JSON.") from exc
    return _object(value, "Release-Akte"), hashlib.sha256(raw).hexdigest()


def validate_release_acceptance(
    summary: dict[str, Any],
    receipt_path: Path,
    *,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """Validate a receipt against *summary* and return a stable snapshot.

    ``now`` exists for deterministic host tests; production callers use the
    current timezone-aware UTC instant.
    """
    if type(summary) is not dict:
        raise ReleaseAcceptanceError("Release-Zusammenfassung ist kein Objekt.")
    try:
        receipt_path = receipt_path.resolve(strict=True)
    except OSError as exc:
        raise ReleaseAcceptanceError(
            f"Release-Akte ist nicht lesbar: {receipt_path}"
        ) from exc
    receipt, receipt_sha256 = _read_json(receipt_path)
    _exact_fields(receipt, {"schema_version", "candidate", "stages", "approval"}, "Release-Akte")
    if type(receipt["schema_version"]) is not int or receipt["schema_version"] != SCHEMA_VERSION:
        raise ReleaseAcceptanceError("Nicht unterstuetzte Release-Akte-Schema-Version.")

    candidate = _object(receipt["candidate"], "candidate")
    _exact_fields(
        candidate,
        {"target", "version", "release_sequence", "file_size", "sha256", "mandatory"},
        "candidate",
    )
    candidate_target = _string(candidate["target"], "candidate.target")
    candidate_version = _string(candidate["version"], "candidate.version")
    candidate_sequence = _positive_int(candidate["release_sequence"], "candidate.release_sequence")
    candidate_size = _positive_int(candidate["file_size"], "candidate.file_size")
    candidate_sha256 = _sha256(candidate["sha256"], "candidate.sha256")
    candidate_mandatory = _strict_bool(candidate["mandatory"], "candidate.mandatory")

    expected_target = _string(summary.get("target"), "summary.target").strip().lower()
    expected_version = _string(summary.get("version"), "summary.version")
    expected_sequence = _positive_int(summary.get("release_sequence"), "summary.release_sequence")
    expected_size = _positive_int(summary.get("file_size"), "summary.file_size")
    expected_sha256 = _sha256(summary.get("sha256"), "summary.sha256")
    expected_mandatory = _strict_bool(summary.get("mandatory"), "summary.mandatory")
    expected_candidate = {
        "target": expected_target,
        "version": expected_version,
        "release_sequence": expected_sequence,
        "file_size": expected_size,
        "sha256": expected_sha256,
        "mandatory": expected_mandatory,
    }
    if (
        candidate_target != expected_candidate["target"]
        or candidate_version != expected_candidate["version"]
        or candidate_sequence != expected_candidate["release_sequence"]
        or candidate_size != expected_candidate["file_size"]
        or candidate_sha256 != expected_candidate["sha256"]
        or candidate_mandatory != expected_candidate["mandatory"]
    ):
        raise ReleaseAcceptanceError(
            "Release-Akte candidate passt nicht exakt zum vorbereiteten Artefakt."
        )

    stages = _object(receipt["stages"], "stages")
    _exact_fields(stages, set(STAGE_NAMES), "stages")
    current = now or dt.datetime.now(dt.timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ReleaseAcceptanceError("Interne Pruefzeit muss eine Zeitzone enthalten.")
    stage_snapshot: dict[str, Any] = {}
    previous_time: dt.datetime | None = None
    for name in STAGE_NAMES:
        stage = _object(stages[name], f"stages.{name}")
        _exact_fields(stage, {"status", "tested_by", "completed_at", "evidence_file", "evidence_sha256"}, f"stages.{name}")
        if _string(stage["status"], f"stages.{name}.status") != "passed":
            raise ReleaseAcceptanceError(f"stages.{name}.status muss passed sein.")
        tested_by = _string(stage["tested_by"], f"stages.{name}.tested_by")
        completed_at = _timestamp(stage["completed_at"], f"stages.{name}.completed_at")
        if completed_at > current:
            raise ReleaseAcceptanceError(f"stages.{name}.completed_at liegt in der Zukunft.")
        if previous_time is not None and completed_at <= previous_time:
            raise ReleaseAcceptanceError(
                "Die Stage-Zeitstempel muessen strikt aufsteigend geordnet sein."
            )
        previous_time = completed_at
        evidence_file = _string(stage["evidence_file"], f"stages.{name}.evidence_file")
        evidence_path = Path(evidence_file)
        if evidence_path.is_absolute() or ".." in evidence_path.parts:
            raise ReleaseAcceptanceError(
                f"stages.{name}.evidence_file muss relativ und innerhalb der Akte liegen."
            )
        try:
            resolved_evidence = (receipt_path.parent / evidence_path).resolve(strict=True)
        except OSError as exc:
            raise ReleaseAcceptanceError(
                f"stages.{name}.evidence_file ist nicht lesbar."
            ) from exc
        try:
            resolved_evidence.relative_to(receipt_path.parent.resolve())
        except ValueError as exc:
            raise ReleaseAcceptanceError(
                f"stages.{name}.evidence_file liegt ausserhalb des Aktenordners."
            ) from exc
        evidence_sha256 = _sha256(stage["evidence_sha256"], f"stages.{name}.evidence_sha256")
        actual_evidence_sha256 = _hash_file(resolved_evidence, f"stages.{name}.evidence_file")
        if actual_evidence_sha256 != evidence_sha256:
            raise ReleaseAcceptanceError(f"stages.{name}.evidence_file Hash stimmt nicht.")
        stage_snapshot[name] = {
            "status": "passed",
            "tested_by": tested_by,
            "completed_at": completed_at.isoformat(),
            "evidence_file": evidence_file,
            "evidence_sha256": actual_evidence_sha256,
        }

    approval = _object(receipt["approval"], "approval")
    _exact_fields(approval, {"status", "approved_by", "approved_at"}, "approval")
    if _string(approval["status"], "approval.status") != "approved":
        raise ReleaseAcceptanceError("approval.status muss approved sein.")
    approved_by = _string(approval["approved_by"], "approval.approved_by")
    approved_at = _timestamp(approval["approved_at"], "approval.approved_at")
    if previous_time is None or approved_at <= previous_time:
        raise ReleaseAcceptanceError(
            "approval.approved_at muss strikt nach allen Stages liegen."
        )
    if approved_at > current:
        raise ReleaseAcceptanceError("approval.approved_at liegt in der Zukunft.")

    return {
        "schema_version": SCHEMA_VERSION,
        "receipt_sha256": receipt_sha256,
        "candidate": {
            "target": candidate_target,
            "version": candidate_version,
            "release_sequence": candidate_sequence,
            "file_size": candidate_size,
            "sha256": candidate_sha256,
            "mandatory": candidate_mandatory,
        },
        "stages": stage_snapshot,
        "approval": {
            "status": "approved",
            "approved_by": approved_by,
            "approved_at": approved_at.isoformat(),
        },
    }


def receipt_path_from_env(env_value, *, root: Path) -> Path:
    raw_path = env_value("OTA_RELEASE_ACCEPTANCE_FILE", "").strip()
    if not raw_path:
        raise ReleaseAcceptanceError(
            "OTA_RELEASE_ACCEPTANCE_FILE ist nicht gesetzt; lokale Release-Akte fehlt."
        )
    return _resolve_receipt_path(raw_path, root)
