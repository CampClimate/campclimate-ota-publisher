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
EXCEPTION_SCHEMA_VERSION = 2
STAGE_NAMES = ("software", "test_firmware", "vehicle")
_SHA256_HEX = frozenset("0123456789abcdef")

# Deliberately deny-by-default until the release owner supplies the identity of
# the final signed BIN.  This is a private, single-candidate binding; it must
# never become an environment-variable or general force-release switch.
_EXCEPTION_ID = "2026-10-20-central-2.2.0.4-seq5"
_EXCEPTION_REASON = "Dann mach mal die aktuelle Central Version fertig für die Cloud und lade Sie hoch\nDar freigegeben werden in diesem Fall"
_EXCEPTION_CANDIDATE = {
    "target": "central",
    "version": "2.2.0.4",
    "release_sequence": 5,
    "file_size": 2134016,
    "sha256": "050001e689e36e4028048f29d27da7c2bf1cf0740efd8bf2eb0cdca21609579a",
    "mandatory": False,
}

# Separate, explicitly authorized initial Central release. Keep its final BIN
# identity unset until the release owner supplies the verified signed artifact.
_CENTRAL_INITIAL_EXCEPTION_ID = "2026-10-24-central-2.2.0.5-seq7-initial-release"
_CENTRAL_INITIAL_EXCEPTION_REASON = (
    "Ach und wir brauchen die aktuelle FW Version der Central natürlich als Initiale Version auch auf SUpabase damit ich sie im Factroy prozess installeiren kann. "
    "Dazu ist sie aktuell freigegeben, da wir noch keine im Feld befidnlichen Systeme haben"
)
_CENTRAL_INITIAL_CANDIDATE = {
    "target": "central",
    "version": "2.2.0.5",
    "release_sequence": 7,
    "file_size": 2154496,
    "sha256": "c4c08f485759a201a27c912150c009444dd95cfaff335f089b5de81ab9d4c1f0",
    "mandatory": False,
}

# Explicitly authorized Outdoor initial release. This exception is bound to
# the exact prepared production BIN; hardware validation remains unclaimed.
_OUTDOOR_INITIAL_EXCEPTION_ID = "2026-10-24-outdoor-1.0.0.0-seq1-initial-release"
_OUTDOOR_INITIAL_EXCEPTION_REASON = (
    "IN diesem Fall Upload druchführen, ist die Initial Version - Da geht es nicht anders"
)
_OUTDOOR_INITIAL_CANDIDATE = {
    "target": "outdoor",
    "version": "1.0.0.0",
    "release_sequence": 1,
    "file_size": 951568,
    "sha256": "d7fe997090c093876dc03844636d52b39b4a7c3a8c92e0c74f760682266e1820",
    "mandatory": False,
}

# Explicit 2026-10-30 approval for the REV 1 GPIO15-only correction.
# Hardware/vehicle acceptance remains open; never reuse this for another BIN.
_OUTDOOR_GPIO15_EXCEPTION_ID = "2026-10-30-outdoor-1.0.0.1-seq2-gpio15"
_OUTDOOR_GPIO15_EXCEPTION_REASON = "Ja, dieses Image veröffentlichen und Factory fortsetzen"
_OUTDOOR_GPIO15_CANDIDATE = {
    "target": "outdoor",
    "version": "1.0.0.1",
    "release_sequence": 2,
    "file_size": 950592,
    "sha256": "de5fc56a067412525c80b99a44b8795e3a3cc26d492ef462e0582d9e81732620",
    "mandatory": False,
}

# Explicit one-release waiver: bench hardware tested, new vehicle test waived.
_BASIC_EXCEPTION_ID = "2026-10-20-basic-2.2.0.2-seq3-sleep-fix"
_BASIC_EXCEPTION_REASON = "Diesen Fix ausdrücklich ohne neuen Fahrzeugtest veröffentlichen"
_BASIC_EXCEPTION_CANDIDATE = {
    "target": "basic",
    "version": "2.2.0.2",
    "release_sequence": 3,
    "file_size": 999440,
    "sha256": "19bb3d2f0476b459854ee17de12d0c168a116c68f96f76ed1737b95c4682fa5d",
    "mandatory": False,
}


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


def _validate_candidate(
    receipt: dict[str, Any], summary: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    candidate = _object(receipt["candidate"], "candidate")
    _exact_fields(
        candidate,
        {"target", "version", "release_sequence", "file_size", "sha256", "mandatory"},
        "candidate",
    )
    candidate_values = {
        "target": _string(candidate["target"], "candidate.target"),
        "version": _string(candidate["version"], "candidate.version"),
        "release_sequence": _positive_int(candidate["release_sequence"], "candidate.release_sequence"),
        "file_size": _positive_int(candidate["file_size"], "candidate.file_size"),
        "sha256": _sha256(candidate["sha256"], "candidate.sha256"),
        "mandatory": _strict_bool(candidate["mandatory"], "candidate.mandatory"),
    }
    expected = {
        "target": _string(summary.get("target"), "summary.target").strip().lower(),
        "version": _string(summary.get("version"), "summary.version"),
        "release_sequence": _positive_int(summary.get("release_sequence"), "summary.release_sequence"),
        "file_size": _positive_int(summary.get("file_size"), "summary.file_size"),
        "sha256": _sha256(summary.get("sha256"), "summary.sha256"),
        "mandatory": _strict_bool(summary.get("mandatory"), "summary.mandatory"),
    }
    if candidate_values != expected:
        raise ReleaseAcceptanceError(
            "Release-Akte candidate passt nicht exakt zum vorbereiteten Artefakt."
        )
    return candidate_values, expected


def _validate_exception_schema2(
    receipt: dict[str, Any],
    summary: dict[str, Any],
    receipt_path: Path,
    receipt_sha256: str,
    *,
    now: dt.datetime | None,
) -> dict[str, Any]:
    _exact_fields(receipt, {"schema_version", "candidate", "stages", "approval", "exception"}, "Release-Akte")
    candidate, _ = _validate_candidate(receipt, summary)
    central_initial_exception = all(
        candidate[key] == _CENTRAL_INITIAL_CANDIDATE[key]
        for key in ("target", "version", "release_sequence", "mandatory")
    )
    outdoor_initial_exception = candidate == _OUTDOOR_INITIAL_CANDIDATE
    outdoor_gpio15_exception = candidate == _OUTDOOR_GPIO15_CANDIDATE
    basic_exception = candidate == _BASIC_EXCEPTION_CANDIDATE
    if outdoor_gpio15_exception:
        binding = _OUTDOOR_GPIO15_CANDIDATE
        exception_id = _OUTDOOR_GPIO15_EXCEPTION_ID
        exception_reason = _OUTDOOR_GPIO15_EXCEPTION_REASON
    elif outdoor_initial_exception:
        binding = _OUTDOOR_INITIAL_CANDIDATE
        exception_id = _OUTDOOR_INITIAL_EXCEPTION_ID
        exception_reason = _OUTDOOR_INITIAL_EXCEPTION_REASON
    elif central_initial_exception:
        binding = _CENTRAL_INITIAL_CANDIDATE
        exception_id = _CENTRAL_INITIAL_EXCEPTION_ID
        exception_reason = _CENTRAL_INITIAL_EXCEPTION_REASON
    elif basic_exception:
        binding = _BASIC_EXCEPTION_CANDIDATE
        exception_id = _BASIC_EXCEPTION_ID
        exception_reason = _BASIC_EXCEPTION_REASON
    else:
        binding = _EXCEPTION_CANDIDATE
        exception_id = _EXCEPTION_ID
        exception_reason = _EXCEPTION_REASON
    if any(binding[key] is None for key in ("file_size", "sha256")):
        raise ReleaseAcceptanceError("Schema-2-Ausnahme ist fuer diesen Kandidaten noch nicht freigeschaltet.")
    if candidate != binding:
        raise ReleaseAcceptanceError("Schema-2-Ausnahme ist nicht an diesen exakten Kandidaten gebunden.")

    exception = _object(receipt["exception"], "exception")
    _exact_fields(exception, {"exception_id", "reason", "evidence_file", "evidence_sha256"}, "exception")
    if _string(exception["exception_id"], "exception.exception_id") != exception_id:
        raise ReleaseAcceptanceError("Unbekannte Schema-2-Ausnahme-ID.")
    if _string(exception["reason"], "exception.reason") != exception_reason:
        raise ReleaseAcceptanceError("Schema-2-Ausnahmegrund stimmt nicht mit der Nutzeranweisung ueberein.")
    evidence_file = _string(exception["evidence_file"], "exception.evidence_file")
    evidence_path = Path(evidence_file)
    if evidence_path.is_absolute() or ".." in evidence_path.parts:
        raise ReleaseAcceptanceError("exception.evidence_file muss relativ und innerhalb der Akte liegen.")
    try:
        resolved_evidence = (receipt_path.parent / evidence_path).resolve(strict=True)
        resolved_evidence.relative_to(receipt_path.parent.resolve())
    except (OSError, ValueError) as exc:
        raise ReleaseAcceptanceError("exception.evidence_file liegt ausserhalb des Aktenordners oder ist nicht lesbar.") from exc
    evidence_sha256 = _sha256(exception["evidence_sha256"], "exception.evidence_sha256")
    if _hash_file(resolved_evidence, "exception.evidence_file") != evidence_sha256:
        raise ReleaseAcceptanceError("exception.evidence_file Hash stimmt nicht.")
    exception_evidence_file = evidence_file

    stages = _object(receipt["stages"], "stages")
    _exact_fields(stages, set(STAGE_NAMES), "stages")
    current = now or dt.datetime.now(dt.timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ReleaseAcceptanceError("Interne Pruefzeit muss eine Zeitzone enthalten.")
    stage_snapshot: dict[str, Any] = {}
    allowed_statuses = {"software": {"passed"}, "test_firmware": {"open", "waived"}, "vehicle": {"open", "waived"}}
    if basic_exception:
        allowed_statuses.update({"test_firmware": {"passed"}, "vehicle": {"waived"}})
    for name in STAGE_NAMES:
        stage = _object(stages[name], f"stages.{name}")
        _exact_fields(stage, {"status", "tested_by", "completed_at", "evidence_file", "evidence_sha256"}, f"stages.{name}")
        status = _string(stage["status"], f"stages.{name}.status")
        if status not in allowed_statuses[name]:
            raise ReleaseAcceptanceError(f"stages.{name}.status ist fuer Schema 2 ungueltig.")
        tested_by = _string(stage["tested_by"], f"stages.{name}.tested_by")
        raw_completed_at = stage["completed_at"]
        if status == "passed":
            completed_at = _timestamp(raw_completed_at, f"stages.{name}.completed_at")
            if completed_at > current:
                raise ReleaseAcceptanceError(f"stages.{name}.completed_at liegt in der Zukunft.")
            if basic_exception and name == "test_firmware":
                software_time = _timestamp(stages["software"]["completed_at"], "stages.software.completed_at")
                if tested_by == "not tested" or completed_at <= software_time:
                    raise ReleaseAcceptanceError("Basic-Ausnahme benoetigt Hardwaretest nach den Softwaretests.")
        else:
            if raw_completed_at is not None:
                raise ReleaseAcceptanceError(f"stages.{name}.completed_at muss bei offener Ausnahme null sein.")
            completed_at = None
            if tested_by != "not tested":
                raise ReleaseAcceptanceError(f"stages.{name}.tested_by muss not tested sein.")
        evidence_file = _string(stage["evidence_file"], f"stages.{name}.evidence_file")
        evidence_path = Path(evidence_file)
        if evidence_path.is_absolute() or ".." in evidence_path.parts:
            raise ReleaseAcceptanceError(f"stages.{name}.evidence_file muss relativ und innerhalb der Akte liegen.")
        try:
            resolved = (receipt_path.parent / evidence_path).resolve(strict=True)
            resolved.relative_to(receipt_path.parent.resolve())
        except (OSError, ValueError) as exc:
            raise ReleaseAcceptanceError(f"stages.{name}.evidence_file ist nicht lesbar oder liegt ausserhalb der Akte.") from exc
        stage_evidence_sha256 = _sha256(stage["evidence_sha256"], f"stages.{name}.evidence_sha256")
        if _hash_file(resolved, f"stages.{name}.evidence_file") != stage_evidence_sha256:
            raise ReleaseAcceptanceError(f"stages.{name}.evidence_file Hash stimmt nicht.")
        if status != "passed":
            try:
                evidence_text = resolved.read_text(encoding="utf-8").casefold()
            except (OSError, UnicodeDecodeError) as exc:
                raise ReleaseAcceptanceError(f"stages.{name}.evidence_file muss lesbaren Ausnahmehinweis enthalten.") from exc
            if not any(marker in evidence_text for marker in ("not performed", "not tested", "nicht durchgeführt", "nicht durchgefuehrt")):
                raise ReleaseAcceptanceError(f"stages.{name}.evidence_file muss die nicht erfolgte Pruefung ausweisen.")
        stage_snapshot[name] = {"status": status, "tested_by": tested_by, "completed_at": completed_at.isoformat() if completed_at else None, "evidence_file": evidence_file, "evidence_sha256": stage_evidence_sha256}

    approval = _object(receipt["approval"], "approval")
    _exact_fields(approval, {"status", "approved_by", "approved_at"}, "approval")
    if _string(approval["status"], "approval.status") != "approved_by_exception":
        raise ReleaseAcceptanceError("approval.status muss approved_by_exception sein.")
    approved_by = _string(approval["approved_by"], "approval.approved_by")
    if approved_by != "Bastian Schnier":
        raise ReleaseAcceptanceError("Schema-2-Ausnahme darf nur von Bastian Schnier freigegeben werden.")
    approved_at = _timestamp(approval["approved_at"], "approval.approved_at")
    if approved_at > current:
        raise ReleaseAcceptanceError("approval.approved_at ist zeitlich ungueltig.")
    return {"schema_version": EXCEPTION_SCHEMA_VERSION, "receipt_sha256": receipt_sha256, "candidate": candidate, "stages": stage_snapshot, "approval": {"status": "approved_by_exception", "approved_by": approved_by, "approved_at": approved_at.isoformat()}, "exception": {"exception_id": exception_id, "reason": exception_reason, "evidence_file": exception_evidence_file, "evidence_sha256": evidence_sha256}}


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
    schema_version = receipt.get("schema_version")
    if type(schema_version) is not int:
        raise ReleaseAcceptanceError("Nicht unterstuetzte Release-Akte-Schema-Version.")
    if schema_version == EXCEPTION_SCHEMA_VERSION:
        return _validate_exception_schema2(
            receipt, summary, receipt_path, receipt_sha256, now=now
        )
    _exact_fields(receipt, {"schema_version", "candidate", "stages", "approval"}, "Release-Akte")
    if schema_version != SCHEMA_VERSION:
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
