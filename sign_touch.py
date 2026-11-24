"""Sign a local Touch OTA candidate and verify its embedded build identity."""

import argparse
import hashlib
import json
from pathlib import Path
import struct

from publisher import env_value
from release_signing import ReleaseManifest, SigningError, TOUCH_TARGETS, sign_manifest, signing_config_from_values


DESCRIPTOR = struct.Struct("<8sQ8s16s32s")
SLOT_BYTES = 0x1e0000


def touch_manifest(image: bytes, target: str, version: str, sequence: int, key_id: str) -> ReleaseManifest:
    if target not in TOUCH_TARGETS or not (0 < len(version) <= 31):
        raise SigningError("Touch-Ziel oder Versionslänge ungültig.")
    if not (24 < len(image) <= SLOT_BYTES) or image[0] != 0xe9:
        raise SigningError("Ungültige ESP32-App oder Image größer als der Touch-OTA-Slot.")
    marker = b"CCFWSEQ1"
    offset = image.find(marker)
    if image.count(marker) != 1 or offset + DESCRIPTOR.size > len(image):
        raise SigningError("Touch-Image muss genau eine vollständige Release-Kennung enthalten.")
    _, actual_sequence, kind, board, build_version = DESCRIPTOR.unpack_from(image, offset)
    manifest = ReleaseManifest(target, version, sequence, len(image), hashlib.sha256(image).hexdigest(), key_id)
    manifest.validate()
    if (kind != b"CCTGTID1" or actual_sequence != sequence
            or board != target.encode("ascii").ljust(16, b"\0")
            or build_version != version.encode("ascii").ljust(32, b"\0")):
        raise SigningError("Displayvariante, Version oder Sequenz stimmen nicht mit dem Image überein.")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--target", choices=sorted(TOUCH_TARGETS), required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--sequence", type=int, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    config = signing_config_from_values(env_value)
    manifest = touch_manifest(args.image.read_bytes(), args.target, args.version, args.sequence, config.key_id)
    signed = sign_manifest(manifest, config)
    with args.manifest.open("x", encoding="utf-8") as output:
        json.dump(signed.to_dict(), output, indent=2)
        output.write("\n")
    print(f"{manifest.target} {manifest.version} #{manifest.release_sequence}: {manifest.sha256}")


if __name__ == "__main__":
    main()
