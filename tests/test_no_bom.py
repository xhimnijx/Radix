"""Guard against UTF-8 BOMs in source files.

Python 3.11 rejects a BOM in a source file with "invalid non-printable character
U+FEFF"; 3.12 and later tolerate it. That difference turned CI red on 3.11 while
3.12 and 3.13 passed, and the BOMs came from a shell that writes one by default --
including the first version of this file, which the test then failed on.

It asks git for the file list rather than walking the tree: `rglob` over the
repository also walks the Rust target directory and the Android build output, which
made the fast suite 4.5x slower for no extra coverage.
"""

import pathlib
import subprocess

BINARY_SUFFIXES = {".png", ".ico", ".jar", ".exe", ".apk", ".bin", ".whl", ".zip"}


def _tracked_files():
    root = pathlib.Path(__file__).resolve().parent.parent
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        # Not a git checkout (a source tarball, say): fall back to nothing rather
        # than silently checking the wrong files.
        return []
    for name in result.stdout.split("\0"):
        if name:
            yield root / name


def test_no_source_file_starts_with_a_byte_order_mark():
    offenders = []
    for path in _tracked_files():
        if not path.is_file() or path.suffix in BINARY_SUFFIXES:
            continue
        if path.read_bytes().startswith(b"\xef\xbb\xbf"):
            offenders.append(str(path))
    assert not offenders, (
        "these files start with a UTF-8 BOM, which Python 3.11 rejects: "
        + ", ".join(offenders)
    )
