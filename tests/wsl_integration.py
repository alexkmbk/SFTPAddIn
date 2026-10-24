"""Verify uploads through the component against the dedicated Debian OpenSSH test service.

Uses copies of data/testData, a unique remote directory and caller-selected local
credential files. Removes only the directory created by this invocation after success.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid

import paramiko


def wsl(distribution, *arguments):
    return subprocess.run(["wsl", "-d", distribution, "-u", "root", "--", *arguments],
                          check=True, capture_output=True, text=True).stdout.strip()


def run(native_host, dll, distribution, user, password_file, host_key_file, port, remote_directory):
    address = wsl(distribution, "hostname", "-I").split()[0]
    password = wsl(distribution, "cat", password_file)
    public = wsl(distribution, "cat", host_key_file).split()
    key = paramiko.Ed25519Key(data=base64.b64decode(public[1]))
    fingerprint = "ssh-ed25519 255 " + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
    directory = remote_directory.rstrip("/") + "/upload-check-" + uuid.uuid4().hex
    client = paramiko.SSHClient()
    client.get_host_keys().add(f"[{address}]:{port}", "ssh-ed25519", key)
    try:
        client.connect(address, port=port, username=user, password=password,
                       allow_agent=False, look_for_keys=False, timeout=10)
        with client.open_sftp() as sftp, tempfile.TemporaryDirectory(prefix="sftp-wsl-upload-") as temporary:
            local = Path(temporary)
            fixtures = Path(__file__).resolve().parents[1] / "data" / "testData"
            shutil.copytree(fixtures, local / "batch")
            originals = sorted(path for path in fixtures.iterdir() if path.is_file())
            if not originals:
                raise RuntimeError("No files in data/testData")
            shutil.copy2(originals[0], local / "single.bin")
            sftp.mkdir(directory)
            environment = dict(os.environ, SFTP_TEST_HOST=address, SFTP_TEST_USER=user,
                               SFTP_TEST_PASSWORD=password, SFTP_TEST_REMOTE=directory)
            subprocess.run([str(native_host), str(dll), str(port), fingerprint, str(local), "upload-smoke"],
                           env=environment, check=True, timeout=120)
            report = json.loads((local / "result.json").read_text(encoding="utf-8"))
            assert sorted(report["uploaded"]) == sorted(path.name for path in originals)
            assert not report["skipped"] and not report["pending"]
            assert not any(path.is_file() for path in (local / "batch").iterdir())
            for original in originals:
                downloaded = local / original.name
                sftp.get(directory + "/" + original.name, str(downloaded))
                assert hashlib.sha256(downloaded.read_bytes()).digest() == hashlib.sha256(original.read_bytes()).digest()
                assert int(sftp.stat(directory + "/" + original.name).st_mtime) == int(original.stat().st_mtime)
            for name in sftp.listdir(directory):
                sftp.remove(directory + "/" + name)
            sftp.rmdir(directory)
            print(f"Debian OpenSSH: {len(originals)} files verified through component; NewerOnly, replacement, DeleteSource, timestamps and SHA-256 passed")
    finally:
        client.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("host", type=Path)
    parser.add_argument("dll", type=Path)
    parser.add_argument("--distribution", default="Debian")
    parser.add_argument("--user", required=True)
    parser.add_argument("--password-file", required=True, help="Local path in WSL; contents are not logged")
    parser.add_argument("--host-key-file", required=True, help="Local Ed25519 PUBLIC host key path in WSL")
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--remote-directory", default="/files")
    args = parser.parse_args()
    run(args.host.resolve(), args.dll.resolve(), args.distribution, args.user,
        args.password_file, args.host_key_file, args.port, args.remote_directory)
