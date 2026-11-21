#!/usr/bin/env python3
"""Restore exact PNG bytes from staged base64 blobs. SHA-256 and PNG dimensions enforced."""
import base64, hashlib, json, struct
from pathlib import Path

root = Path(__file__).resolve().parents[1]
for manifest in sorted((root / ".transfer/manifests").glob("*.json")):
    data = json.loads(manifest.read_text(encoding="utf-8"))
    for item in data["assets"]:
        target = root / item["filename"]
        if target.parent != root or target.suffix.lower() != ".png":
            raise SystemExit("Unsafe destination: " + str(target))
        if target.exists() and hashlib.sha256(target.read_bytes()).hexdigest() == item["sha256"]:
            print("Already verified:", target.name)
            continue
        joined = "".join((root / part).read_text(encoding="utf-8") for part in item["chunks"])
        binary = base64.b64decode("".join(joined.split()), validate=True)
        digest = hashlib.sha256(binary).hexdigest()
        if digest != item["sha256"]:
            raise SystemExit(f"Checksum mismatch for {target.name}: {digest}")
        if not binary.startswith(b"\\x89PNG\\r\\n\\x1a\\n"):
            raise SystemExit("Not PNG: " + target.name)
        width, height = struct.unpack(">II", binary[16:24])
        if (width,height) != tuple(item["dimensions"]):
            raise SystemExit(f"Wrong dimensions {width}x{height}: {target.name}")
        target.write_bytes(binary)
        print("Restored:", target.name, len(binary), "bytes")
    for item in data["assets"]:
        for part in item["chunks"]:
            (root / part).unlink(missing_ok=True)
