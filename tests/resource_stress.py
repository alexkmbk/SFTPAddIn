"""Run exact Debug CRT and Windows handle checks against an isolated SFTP server."""
import argparse
import logging
import os
from pathlib import Path
import subprocess
import tempfile

from integration import Server


def run(executable, kex, cycles, faults):
    with tempfile.TemporaryDirectory(prefix="sftp-resources-") as temporary:
        root = Path(temporary)
        remote = root / "remote"
        local = root / "local"
        remote.mkdir()
        local.mkdir()
        (remote / "uploads" / "close-stall").mkdir(parents=True)
        (remote / "close-stall").mkdir()
        (remote / "payload.bin").write_bytes(bytes(range(256)) * 16)
        (remote / "empty.bin").touch()
        (local / "source.bin").write_bytes(bytes(range(256)) * 16)
        with Server(remote, kex=kex) as server:
            print("Resource stress KEX: " + (kex or "default"), flush=True)
            environment = dict(os.environ, SFTP_STRESS_CYCLES=str(cycles), SFTP_STRESS_FAULTS=str(faults))
            subprocess.run([str(executable), str(server.port), server.fingerprint, str(local)],
                           env=environment, check=True, timeout=180)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("executable", type=Path)
    parser.add_argument("--kex")
    parser.add_argument("--cycles", type=int, default=50)
    parser.add_argument("--faults", type=int, default=4)
    args = parser.parse_args()
    logging.getLogger("paramiko").setLevel(logging.CRITICAL)
    run(args.executable.resolve(), args.kex, args.cycles, args.faults)
