"""Isolated password-authenticated SFTP server and Native API integration tests.

Only listens on 127.0.0.1 and operates inside a temporary directory.
Run with the host executable and DLL of the SAME architecture.
"""
import argparse
import base64
import errno
import hashlib
import io
import json
import logging
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess
import tempfile
import threading
import time

import paramiko
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from paramiko.sftp import CMD_INIT, CMD_VERSION, CMD_CLOSE, SFTPError

PAYLOAD_SIZE = 300123
LARGE_SIZE = 100 * 1024 * 1024


def payload(offset, length):
    start = offset % 251
    return (bytes(range(251)) * ((start + length + 250) // 251))[start:start + length]


class Authentication(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        return (paramiko.AUTH_SUCCESSFUL if username == "test" and password == "test-password"
                else paramiko.AUTH_FAILED)

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, channel_id):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


class VirtualHandle(paramiko.SFTPHandle):
    def __init__(self, size, kind, on_read=None):
        super().__init__()
        self.size = size
        self.kind = kind
        self.on_read = on_read

    def stat(self):
        attrs = paramiko.SFTPAttributes()
        attrs.st_size = self.size
        attrs.st_mode = stat.S_IFREG | 0o644
        return attrs

    def close(self):
        if self.kind == "close-stall":
            time.sleep(2)
        return paramiko.SFTP_OK

    def read(self, offset, length):
        if self.on_read:
            self.on_read()
            self.on_read = None
        if self.kind == "broken" and offset >= 32768:
            return paramiko.SFTP_FAILURE
        if self.kind == "stall":
            time.sleep(5)
        return payload(offset, max(0, min(length, self.size - offset)))


class FileSystem(paramiko.SFTPServerInterface):
    def __init__(self, server, *, root):
        super().__init__(server)
        self.root = Path(root).resolve()

    def local(self, path):
        result = (self.root / path.lstrip("/")).resolve()
        if not result.is_relative_to(self.root):
            raise PermissionError(errno.EACCES, "Outside test root")
        return result

    def virtual(self, path):
        sizes = {"/large.bin": (LARGE_SIZE, "normal"), "/broken.bin": (PAYLOAD_SIZE, "broken"),
                 "/stall.bin": (PAYLOAD_SIZE, "stall"), "/close-stall.bin": (4096, "close-stall"),
                 "/close-denied.bin": (4096, "close-denied")}
        return sizes.get(path)

    def list_folder(self, path):
        try:
            result = []
            for item in self.local(path).iterdir():
                attrs = paramiko.SFTPAttributes.from_stat(item.stat())
                attrs.filename = item.name
                result.append(attrs)
            if path == "/":
                for name in ['quoted"name.txt', "line\nbreak.txt", "slash\\name.txt", "large.bin"]:
                    attrs = paramiko.SFTPAttributes()
                    attrs.filename = name
                    attrs.st_size = LARGE_SIZE if name == "large.bin" else 0
                    attrs.st_mode = stat.S_IFREG | 0o644
                    result.append(attrs)
            return result
        except OSError as error:
            return paramiko.SFTPServer.convert_errno(error.errno)

    def stat(self, path):
        try:
            if path in ("/denied.bin", "/uploads/batch/02-denied.bin"):
                return paramiko.SFTP_PERMISSION_DENIED
            if path == "/unknown":
                return paramiko.SFTPAttributes()
            if path == "/uploads/unknown-time.bin":
                attrs = paramiko.SFTPAttributes()
                attrs.st_mode = stat.S_IFREG | 0o644
                return attrs
            if path == "/link.bin":
                return VirtualHandle(PAYLOAD_SIZE, "normal").stat()
            if path == "/broken-link":
                return paramiko.SFTP_NO_SUCH_FILE
            if value := self.virtual(path):
                return VirtualHandle(*value).stat()
            return paramiko.SFTPAttributes.from_stat(self.local(path).stat())
        except OSError as error:
            return paramiko.SFTPServer.convert_errno(error.errno)

    def lstat(self, path):
        if path in ("/link.bin", "/broken-link"):
            attrs = paramiko.SFTPAttributes()
            attrs.st_mode = stat.S_IFLNK | 0o777
            attrs.st_size = len("payload.bin")
            return attrs
        return self.stat(path)

    def open(self, path, flags, attrs):
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC):
            if not path.startswith("/uploads/"):
                return paramiko.SFTP_PERMISSION_DENIED
            try:
                fd = os.open(self.local(path), flags | getattr(os, "O_BINARY", 0), 0o644)
                handle = paramiko.SFTPHandle(flags)
                handle.writefile = os.fdopen(fd, "wb", buffering=0)
                handle.stat = lambda: paramiko.SFTPAttributes.from_stat(os.fstat(handle.writefile.fileno()))
                def chattr(attributes):
                    if path.startswith("/uploads/setstat-fail/"):
                        return paramiko.SFTP_PERMISSION_DENIED
                    paramiko.SFTPServer.set_file_attr(str(self.local(path)), attributes)
                    return paramiko.SFTP_OK
                handle.chattr = chattr
                if path.startswith("/uploads/close-stall/"):
                    original_close = handle.close
                    def delayed_close():
                        result = original_close()
                        time.sleep(2)
                        return result
                    handle.close = delayed_close
                if path.startswith("/uploads/write-fail/"):
                    handle.write = lambda offset, data: paramiko.SFTP_FAILURE
                return handle
            except OSError as error:
                return paramiko.SFTPServer.convert_errno(error.errno)
        if value := self.virtual(path):
            return VirtualHandle(*value)
        if path == "/race.bin":
            target = self.root.parent / "output" / "новая папка" / "nested" / "race.bin"
            return VirtualHandle(PAYLOAD_SIZE, "normal", lambda: target.write_bytes(b"concurrent"))
        try:
            handle = paramiko.SFTPHandle(flags)
            handle.readfile = self.local(path).open("rb")
            handle.stat = lambda: paramiko.SFTPAttributes.from_stat(os.fstat(handle.readfile.fileno()))
            return handle
        except OSError as error:
            return paramiko.SFTPServer.convert_errno(error.errno)

    def remove(self, path):
        try:
            self.local(path).unlink()
            if path == "/uncertain.bin":
                time.sleep(5)  # Applied operation, but the response is lost to a client timeout.
            return paramiko.SFTP_OK
        except OSError as error:
            return paramiko.SFTPServer.convert_errno(error.errno)

    def rename(self, oldpath, newpath):
        try:
            if newpath == "/uploads/rename-fail.bin":
                return paramiko.SFTP_PERMISSION_DENIED
            if self.local(newpath).exists():
                return paramiko.SFTP_FAILURE
            self.local(oldpath).rename(self.local(newpath))
            if newpath == "/uploads/uncertain-upload.bin":
                time.sleep(5)
            return paramiko.SFTP_OK
        except OSError as error:
            return paramiko.SFTPServer.convert_errno(error.errno)

    def posix_rename(self, oldpath, newpath):
        if oldpath == "/unsupported.bin" or newpath == "/uploads/no-replace.bin":
            return paramiko.SFTP_OP_UNSUPPORTED
        try:
            os.replace(self.local(oldpath), self.local(newpath))
            return paramiko.SFTP_OK
        except OSError as error:
            return paramiko.SFTPServer.convert_errno(error.errno)


class ProtocolServer(paramiko.SFTPServer):
    def __init__(self, *args, advertise_posix=True, **kwargs):
        self.advertise_posix = advertise_posix
        super().__init__(*args, **kwargs)
        self.delayed_folders = set()

    def _open_folder(self, request_number, path):
        before = set(self.folder_table)
        super()._open_folder(request_number, path)
        if path == "/close-stall":
            self.delayed_folders.update(set(self.folder_table) - before)

    def _process(self, packet_type, request_number, message):
        if packet_type == CMD_CLOSE:
            handle = paramiko.Message(message.get_remainder()).get_binary()
            if handle in self.file_table and getattr(self.file_table[handle], "kind", None) == "close-denied":
                self.file_table.pop(handle).close()
                self._send_status(request_number, paramiko.SFTP_PERMISSION_DENIED)
                return
            if handle in self.delayed_folders:
                self.delayed_folders.discard(handle)
                time.sleep(2)
        super()._process(packet_type, request_number, message)

    def _send_server_version(self):
        packet_type, data = self._read_packet()
        if packet_type != CMD_INIT:
            raise SFTPError("Expected SFTP INIT")
        message = paramiko.Message()
        message.add_int(3)
        if self.advertise_posix:
            message.add_string("posix-rename@openssh.com")
            message.add_string("1")
        self._send_packet(CMD_VERSION, message)
        return struct.unpack(">I", data[:4])[0]


class Server:
    def __init__(self, root, advertise_posix=True, ed25519=False, kex=None):
        self.kex = kex
        if ed25519:
            private = Ed25519PrivateKey.generate().private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption())
            self.key = paramiko.Ed25519Key(file_obj=io.StringIO(private.decode("ascii")))
            self.extra_key = paramiko.ECDSAKey.generate()
        else:
            self.key = paramiko.RSAKey.generate(2048)
            self.extra_key = None
        bits = 255 if ed25519 else self.key.get_bits()
        self.fingerprint = f"{self.key.get_name()} {bits} " + base64.b64encode(hashlib.sha256(self.key.asbytes()).digest()).decode().rstrip("=")
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen()
        self.socket.settimeout(0.5)
        self.port = self.socket.getsockname()[1]
        self.root = root
        self.advertise_posix = advertise_posix
        self.stopped = threading.Event()
        self.transports = []
        self.thread = threading.Thread(target=self.accept, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def accept(self):
        while not self.stopped.is_set():
            try:
                client, _ = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self.connection, args=(client,), daemon=True).start()

    def connection(self, client):
        transport = paramiko.Transport(client)
        self.transports.append(transport)
        try:
            if self.kex:
                transport.get_security_options().kex = (self.kex,)
            transport.add_server_key(self.key)
            if self.extra_key is not None:
                transport.add_server_key(self.extra_key)
            transport.set_subsystem_handler("sftp", ProtocolServer, FileSystem, root=self.root, advertise_posix=self.advertise_posix)
            transport.start_server(server=Authentication())
            while transport.is_active() and not self.stopped.wait(0.1):
                pass
        except (EOFError, OSError, paramiko.SSHException):
            pass  # Expected on a rejected pin, wrong password, or timeout.
        finally:
            transport.close()

    def __exit__(self, *_):
        self.stopped.set()
        self.socket.close()
        for transport in self.transports:
            transport.close()
        self.thread.join(timeout=2)


def run(host, dll):
    with tempfile.TemporaryDirectory(prefix="sftp-addin-test-") as folder:
        root = Path(folder) / "remote"
        output = Path(folder) / "output"
        root.mkdir()
        output.mkdir()
        (root / "archive").mkdir()
        for name in ["payload.bin", "Отчёт.bin", "move.bin"]:
            (root / name).write_bytes(payload(0, PAYLOAD_SIZE))
        (root / "empty.bin").touch()
        (root / "collision.bin").write_bytes(b"source")
        (root / "archive" / "collision.bin").write_bytes(b"destination")
        for name in ["replace.bin", "unsupported.bin", "uncertain.bin"]:
            (root / name).write_bytes(b"source")
            (root / "archive" / name).write_bytes(b"destination")
        uploads = root / "uploads"
        for name in ["batch", "all", "write-fail", "setstat-fail"]:
            (uploads / name).mkdir(parents=True)
        for name in ["no-replace.bin", "write-fail/target.bin", "setstat-fail/target.bin"]:
            (uploads / name).write_bytes(b"previous destination")
        (uploads / "batch" / "00-skip.bin").write_bytes(b"newer remote")
        os.utime(uploads / "batch" / "00-skip.bin", (1700000001, 1700000001))
        upload_source = output / "upload-source"
        upload_source.mkdir()
        for name in ["normal.bin", "Отчёт.bin", "delete.bin", "readonly.bin"]:
            (upload_source / name).write_bytes(payload(0, PAYLOAD_SIZE))
            os.utime(upload_source / name, (1700000000, 1700000000))
        (upload_source / "empty.bin").touch()
        for folder in ["batch-source", "all-source", "empty-source"]:
            (output / folder).mkdir()
        for name in ["00-skip.bin", "01-good.bin", "02-denied.bin", "03-pending.bin"]:
            (output / "batch-source" / name).write_bytes(b"batch payload")
            os.utime(output / "batch-source" / name, (1700000000, 1700000000))
        for name in ["a.bin", "Отчёт.bin"]:
            (output / "all-source" / name).write_bytes(b"all payload")
        (output / "all-source" / "nested").mkdir()
        (output / "all-source" / "nested" / "not-uploaded.bin").write_bytes(b"nested")
        with Server(root) as server:
            result = subprocess.run([str(host), str(dll), str(server.port), server.fingerprint, str(output)],
                                    capture_output=True, timeout=180)
        print(result.stdout.decode("utf-8", errors="replace"), end="")
        if result.returncode:
            print(result.stderr.decode("utf-8", errors="replace"), end="")
            raise RuntimeError(f"Native host exited with {result.returncode}")
        entries = json.loads((output / "listing.json").read_text(encoding="utf-8"))
        names = {entry["name"] for entry in entries}
        assert {'quoted"name.txt', "line\nbreak.txt", "slash\\name.txt", "Отчёт.bin"} <= names
        assert all(entry["path"] == "/" + entry["name"] for entry in entries)
        info = json.loads((output / "stat.json").read_text(encoding="utf-8"))
        listing_info = next(entry for entry in entries if entry["name"] == "payload.bin")
        assert info.pop("exists") is True and info == listing_info
        error = json.loads((output / "error.json").read_text(encoding="utf-8"))
        assert error["operation"] == "Stat" and error["remotePath"] == "/denied.bin" and error["sftpCode"] == 3
        assert error["connectionLost"] is False and error["outcomeUnknown"] is False
        uncertain = json.loads((output / "uncertain.json").read_text(encoding="utf-8"))
        assert uncertain["operation"] == "DeleteFile" and uncertain["connectionLost"] and uncertain["outcomeUnknown"]
        for name in ["payload.bin", "Отчёт.bin"]:
            assert (output / "новая папка" / "nested" / name).read_bytes() == payload(0, PAYLOAD_SIZE)
        large = output / "новая папка" / "nested" / "large.bin"
        with large.open("rb") as stream:
            offset = 0
            while chunk := stream.read(1024 * 1024):
                assert chunk == payload(offset, len(chunk))
                offset += len(chunk)
            assert offset == LARGE_SIZE
        assert (root / "collision.bin").read_bytes() == b"source"
        assert (root / "archive" / "collision.bin").read_bytes() == b"destination"
        assert not (root / "replace.bin").exists()
        assert (root / "archive" / "replace.bin").read_bytes() == b"source"
        assert (root / "unsupported.bin").read_bytes() == b"source"
        assert (root / "archive" / "unsupported.bin").read_bytes() == b"destination"
        assert not (root / "move.bin").exists()
        assert not (root / "archive" / "renamed.bin").exists()
        assert not (root / "uncertain.bin").exists()
        assert (uploads / "normal.bin").read_bytes() == payload(0, PAYLOAD_SIZE)
        assert int((uploads / "normal.bin").stat().st_mtime) == 1700000001
        assert (uploads / "empty.bin").read_bytes() == b""
        assert (uploads / "Отчёт.bin").read_bytes() == payload(0, PAYLOAD_SIZE)
        assert (uploads / "large.bin").read_bytes() == large.read_bytes()
        assert not (upload_source / "delete.bin").exists()
        assert (upload_source / "readonly.bin").exists()
        assert (uploads / "readonly.bin").read_bytes() == payload(0, PAYLOAD_SIZE)
        for name in ["no-replace.bin", "write-fail/target.bin", "setstat-fail/target.bin"]:
            assert (uploads / name).read_bytes() == b"previous destination"
        assert not (uploads / "rename-fail.bin").exists()
        assert (uploads / "uncertain-upload.bin").read_bytes() == payload(0, PAYLOAD_SIZE)
        batch_error = json.loads((output / "upload-batch-error.json").read_text(encoding="utf-8"))
        assert batch_error["operation"] == "PutFiles" and batch_error["sftpCode"] == 3
        assert batch_error["upload"]["uploaded"] == ["01-good.bin"]
        assert batch_error["upload"]["skipped"] == ["00-skip.bin"]
        assert batch_error["upload"]["pending"] == ["03-pending.bin"]
        assert batch_error["upload"]["failedFile"] == "02-denied.bin"
        assert not (output / "batch-source" / "01-good.bin").exists()
        assert all((output / "batch-source" / name).exists() for name in ["00-skip.bin", "02-denied.bin", "03-pending.bin"])
        batch_result = json.loads((output / "upload-batch-result.json").read_text(encoding="utf-8"))
        assert batch_result["uploaded"] == ["a.bin", "Отчёт.bin"] and batch_result["skipped"] == []
        assert not (uploads / "all" / "nested").exists()
        assert not list(uploads.rglob(".sftp-*.tmp"))
        deletion_error = json.loads((output / "upload-delete-error.json").read_text(encoding="utf-8"))
        assert deletion_error["upload"]["transferCompleted"] and not deletion_error["upload"]["sourceDeleted"]
        unknown_upload = json.loads((output / "upload-uncertain.json").read_text(encoding="utf-8"))
        assert unknown_upload["connectionLost"] and unknown_upload["outcomeUnknown"]
        with Server(root, advertise_posix=False) as server:
            rejected = subprocess.run([str(host), str(dll), str(server.port), server.fingerprint, str(output), "no-posix"],
                                      capture_output=True, timeout=30)
        if rejected.returncode:
            raise RuntimeError(rejected.stderr.decode("utf-8", errors="replace"))
        assert (root / "unsupported.bin").read_bytes() == b"source"
        assert (root / "archive" / "unsupported.bin").read_bytes() == b"destination"
        with Server(root, ed25519=True) as server:
            checked = subprocess.run([str(host), str(dll), str(server.port), server.fingerprint, str(output), "ed25519"],
                                     capture_output=True, timeout=30)
        if checked.returncode:
            raise RuntimeError(checked.stderr.decode("utf-8", errors="replace"))
        print("JSON, 100 MiB download/upload, Stat, move/replace, PutFile/PutFiles, NewerOnly/DeleteSource, partial failure, unknown outcome and WinSCP pins verified")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("host", type=Path)
    parser.add_argument("dll", type=Path)
    args = parser.parse_args()
    logging.getLogger("paramiko").setLevel(logging.CRITICAL)
    run(args.host.resolve(), args.dll.resolve())
