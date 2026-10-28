"""Offline ZIP manifest verifier for the HunterQA source release.

Rejects path traversal, duplicate entries, unexpected members, size abuse,
mismatched digests and malformed manifests. Never extracts or executes files.
"""
import argparse
import hashlib
import json
import re
import stat
import zipfile
from pathlib import PurePosixPath

MAX_FILES = 2000
MAX_BYTES = 100_000_000
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _safe_name(name):
    path = PurePosixPath(name)
    return (isinstance(name, str) and name.startswith("HunterQA-AI/")
            and len(path.parts) >= 2 and path.as_posix() == name
            and all(piece not in {".", ".."} for piece in path.parts)
            and not any(ord(char) < 32 or ord(char) == 127 or char in "\\:" for char in name))


def verify_archive(path):
    with zipfile.ZipFile(path, "r") as archive:
        entries = archive.infolist()
        if not entries or len(entries) > MAX_FILES:
            raise ValueError("Archive entry count outside bound")
        by_name = {}
        total = 0
        for info in entries:
            name = info.filename
            file_type = stat.S_IFMT(info.external_attr >> 16)
            if (name in by_name or not _safe_name(name)
                    or file_type not in (0, stat.S_IFREG)
                    or info.is_dir() or info.file_size > 2_000_000):
                raise ValueError("Unsafe or duplicate release archive member")
            total += info.file_size
            if total > MAX_BYTES:
                raise ValueError("Archive exceeds total uncompressed size bound")
            by_name[name] = info
        manifest_name = "HunterQA-AI/RELEASE_MANIFEST.json"
        if manifest_name not in by_name:
            raise ValueError("Missing manifest")
        manifest = json.loads(archive.read(manifest_name))
        if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
            raise ValueError("Invalid manifest")
        expected = set()
        for item in manifest["files"]:
            if not isinstance(item, dict):
                raise ValueError("Invalid manifest row")
            rel = item.get("path")
            sha = item.get("sha256")
            size = item.get("bytes")
            if (not isinstance(rel, str) or not rel or rel.startswith("/")
                    or not _safe_name("HunterQA-AI/" + rel)
                    or not isinstance(sha, str) or not SHA256.fullmatch(sha)
                    or type(size) is not int or not 0 <= size <= 2_000_000):
                raise ValueError("Malformed file metadata")
            name = "HunterQA-AI/" + rel
            if name in expected or name not in by_name:
                raise ValueError("Duplicated or missing file")
            expected.add(name)
            contents = archive.read(name)
            if len(contents) != size or hashlib.sha256(contents).hexdigest() != sha:
                raise ValueError("Release file SHA-256 mismatch")
        if set(by_name) != expected | {manifest_name}:
            raise ValueError("Unexpected unlisted archive file")
    return len(expected)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("archive")
    args = parser.parse_args()
    count = verify_archive(args.archive)
    print(f"PASS: verified {count} files against source release SHA-256 manifest")


if __name__ == "__main__":
    main()
