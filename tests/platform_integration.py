"""Build an isolated empty 1C infobase and test a DLL or ZIP in a real client.

Requires a locally installed, licensed 1C client. Does not modify COM registration
or any existing infobases. Windows subprocesses are launched without visible UI.
"""
import argparse
import json
import logging
from pathlib import Path
import shutil
import subprocess
import tempfile

from integration import Server, payload, PAYLOAD_SIZE


def command(exe, arguments, log):
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = subprocess.SW_HIDE
    process = subprocess.run([str(exe), *map(str, arguments), "/DisableStartupMessages",
                              "/DisableStartupDialogs", "/Out", str(log)],
                             creationflags=subprocess.CREATE_NO_WINDOW, startupinfo=startup, timeout=90)
    if process.returncode:
        message = log.read_text(encoding="utf-8-sig", errors="replace") if log.exists() else ""
        raise RuntimeError(f"1C exited with {process.returncode}: {message}")


def run(exe, package):
    with tempfile.TemporaryDirectory(prefix="sftp-1c-") as temporary:
        root = Path(temporary)
        base = root / "base"
        source = root / "config"
        source.mkdir()
        command(exe, ["CREATEINFOBASE", f'File={base};'], root / "create.log")
        command(exe, ["DESIGNER", "/F", base, "/DumpConfigToFiles", source], root / "dump.log")
        (source / "Ext").mkdir()
        shutil.copyfile(Path(__file__).with_name("ManagedApplicationModule.bsl"), source / "Ext" / "ManagedApplicationModule.bsl")
        command(exe, ["DESIGNER", "/F", base, "/LoadConfigFromFiles", source, "/UpdateDBCfg"], root / "load.log")
        remote = root / "remote"
        remote.mkdir()
        (remote / "archive").mkdir()
        (remote / "uploads").mkdir()
        upload_source = root / "upload-source"
        upload_source.mkdir()
        for name in ["a.bin", "Отчёт.bin"]:
            (upload_source / name).write_bytes(payload(0, PAYLOAD_SIZE))
        for name in ["payload.bin", "move.bin"]:
            (remote / name).write_bytes(payload(0, PAYLOAD_SIZE))
        (remote / "empty.bin").touch()
        with Server(remote) as server:
            parameters = {
                "Пакет": str(package), "Архив": package.suffix.lower() == ".zip",
                "Порт": server.port, "Отпечаток": server.fingerprint,
                "ДвоичныйФайл": str(root / "binary.bin"), "Папка": str(root / "downloads"),
                "ПапкаОтправки": str(upload_source),
                "Результат": str(root / "result.txt"),
            }
            settings = root / "settings.json"
            settings.write_text(json.dumps(parameters, ensure_ascii=False), encoding="utf-8")
            command(exe, ["ENTERPRISE", "/F", base, "/C", settings], root / "client.log")
        result = root / "result.txt"
        if not result.exists():
            raise RuntimeError("1C did not produce a result: " + (root / "client.log").read_text(encoding="utf-8-sig", errors="replace"))
        message = result.read_text(encoding="utf-8-sig").strip()
        if message != "OK":
            raise RuntimeError(message)
        assert (root / "binary.bin").read_bytes() == payload(0, PAYLOAD_SIZE)
        assert (root / "downloads" / "renamed.bin").read_bytes() == payload(0, PAYLOAD_SIZE)
        assert not (remote / "move.bin").exists()
        assert not (remote / "archive" / "renamed.bin").exists()
        for name in ["client-single.bin", "a.bin", "Отчёт.bin"]:
            assert (remote / "uploads" / name).read_bytes() == payload(0, PAYLOAD_SIZE)
        assert not list(upload_source.iterdir())
        print("Real 1C client passed: attach, JSON, BinaryData, Stat, GetFile, PutFile/NewerOnly, PutFiles/DeleteSource, diagnostics, move/delete")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("exe", type=Path, help="Matching 1cv8.exe")
    parser.add_argument("package", type=Path, help="DLL or ZIP")
    args = parser.parse_args()
    logging.getLogger("paramiko").setLevel(logging.CRITICAL)
    run(args.exe.resolve(), args.package.resolve())
