"""Verify the scoped GHSA input files against the pinned upstream archive."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile

from backport import SOURCES, train_of


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help="Pinned GHSA .tar.gz archive")
    args = parser.parse_args()
    manifest = json.loads((SOURCES / "snapshot_manifest.json").read_text(encoding="utf-8"))
    digest = hashlib.sha256()
    with args.archive.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != manifest["ghsa_archive"]["sha256"]:
        raise ValueError("GHSA archive SHA-256 does not match the pinned snapshot")

    # Reproduce the package filter only. backport.py applies the date and version filters.
    seen = set()
    scanned = 0
    with tarfile.open(args.archive, "r|gz") as archive:
        for member in archive:
            if not member.isfile() or "/advisories/github-reviewed/" not in member.name or not member.name.endswith(".json"):
                continue
            with archive.extractfile(member) as stream:
                raw = stream.read()
            data = json.loads(raw)
            scanned += 1
            packages = [a["package"]["name"] for a in data.get("affected", [])
                        if a.get("package", {}).get("ecosystem") == "Maven"]
            if not any(train_of(name) for name in packages):
                continue
            name = data["id"] + ".json"
            if name in seen or (SOURCES / "ghsa" / name).read_bytes() != raw:
                raise ValueError(f"Scoped input differs from the archive: {name}")
            seen.add(name)
    assert scanned == manifest["ghsa_reviewed_records_scanned"]
    assert len(seen) == manifest["ghsa_scope_records_saved"]
    assert seen == {p.name for p in (SOURCES / "ghsa").glob("*.json")}
    print(f"PASS: {scanned:,} reviewed records scanned; {len(seen)} bundled records matched byte for byte.")


if __name__ == "__main__":
    main()
