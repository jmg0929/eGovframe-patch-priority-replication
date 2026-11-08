"""Run the paper analyses in dependency order and verify the release hashes."""
import argparse
import hashlib
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
COMMANDS = [
    ["egovframe_priority_reproduce.py"],
    ["egovframe_priority_review.py"],
    ["backport.py"],
    ["bridge.py"],
    ["bridge.py", "--value-density", "diffuse"],
    ["integration_checks.py"],
    ["reviewer_checks.py"],
    ["paper_checks.py"],
]


def verify(manifest):
    records = (ROOT / manifest).read_text(encoding="utf-8").splitlines()
    for line in records:
        expected, name = line.split("  ", 1)
        path = ROOT / name
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f"SHA-256 mismatch: {name}")
    print(f"Verified {len(records)} entries from {manifest}.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-checksums", action="store_true",
                        help="Run the scientific checks without comparing the release hashes.")
    args = parser.parse_args()
    if not args.skip_checksums:
        verify("INPUT_SHA256SUMS.txt")
    for command in COMMANDS:
        subprocess.run([sys.executable, "-X", "utf8", "-B", *command], cwd=ROOT, check=True)
    if not args.skip_checksums:
        verify("RESULT_SHA256SUMS.txt")


if __name__ == "__main__":
    main()
