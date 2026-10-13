"""Build a CI file index from ccze downloaded using authenticated Debian indexes."""

import hashlib
from pathlib import Path
import subprocess

directory = Path("/opt/rzandal-package-repo")
archives = list(directory.glob("ccze_*.deb"))
assert len(archives) == 1, archives
archive = archives[0]
control = subprocess.check_output(["dpkg-deb", "--field", str(archive)], text=True)
data = archive.read_bytes()
(directory / "Packages").write_text(control.rstrip() + "\n" +
    f"Filename: {archive.name}\nSize: {len(data)}\n" +
    f"MD5sum: {hashlib.md5(data).hexdigest()}\nSHA256: {hashlib.sha256(data).hexdigest()}\n\n")
