"""Test the add-in in a real 1C server context using an MCP Execute(code) tool.

Only uses temporary local SFTP files; does not create or update infobase records.
The caller must explicitly authorize the target MCP endpoint for code execution.
"""
import argparse
import json
import logging
import os
from pathlib import Path
import re
import tempfile
import urllib.request
import xml.etree.ElementTree as ET

from integration import Server, payload, PAYLOAD_SIZE


def rpc(endpoint, method, params, opener):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode("utf-8")
    request = urllib.request.Request(endpoint, data=body, headers={"Content-Type": "application/json", "Accept": "application/json"})
    with opener.open(request, timeout=120) as response:
        result = json.load(response)
    if "error" in result:
        raise RuntimeError(result["error"])
    return result["result"]


def literal(value):
    return '"' + str(value).replace('"', '""') + '"'


def run(endpoint, package, temp_root, publication, user):
    opener = urllib.request.build_opener()
    if publication:
        # Reuse the explicitly selected publication's credentials in memory only.
        connection = ET.parse(publication).getroot().attrib["ib"]
        fields = {}
        for match in re.finditer(r'(?:^|;)\s*(Usr|Pwd)\s*=\s*(?:"((?:[^"]|"")*)"|([^;]*))', connection, re.I):
            fields[match[1].lower()] = (match[2] if match[2] is not None else match[3]).replace('""', '"').strip()
        if "usr" not in fields:
            raise RuntimeError("Selected publication has no configured Usr credential")
        passwords = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        passwords.add_password(None, endpoint, fields["usr"], fields.get("pwd", ""))
        opener = urllib.request.build_opener(urllib.request.HTTPBasicAuthHandler(passwords))
    elif user:
        passwords = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        passwords.add_password(None, endpoint, user, os.environ.get("MCP_HTTP_PASSWORD", ""))
        opener = urllib.request.build_opener(urllib.request.HTTPBasicAuthHandler(passwords))
    tools = rpc(endpoint, "tools/list", {}, opener)["tools"]
    execute = next((tool for tool in tools if tool["name"] == "Execute"), None)
    if execute is None or "code" not in execute["inputSchema"].get("properties", {}):
        raise RuntimeError("MCP Execute(code) is not available")
    with tempfile.TemporaryDirectory(prefix="sftp-mcp-", dir=temp_root) as temporary:
        root = Path(temporary)
        remote = root / "remote"
        remote.mkdir()
        (remote / "archive").mkdir()
        for name in ["payload.bin", "move.bin"]:
            (remote / name).write_bytes(payload(0, PAYLOAD_SIZE))
        (remote / "empty.bin").touch()
        with Server(remote) as server:
            location = literal(package)
            if package.suffix.lower() == ".zip":
                location = f"PutToTempStorage(New BinaryData({location}))"
            code = f'''
// Exercise the add-in without writing any infobase records.
Location = {location};
If Not AttachAddIn(Location, "SFTPAddInMCP", AddInType.Native) Then
    Raise "SFTPAddIn could not be attached";
EndIf;
Component = New("AddIn.SFTPAddInMCP.SFTP");
Component.Timeout = 10;
Component.Connect("127.0.0.1", {server.port}, "test", "test-password", {literal(server.fingerprint)});
Try
    Reader = New JSONReader;
    Reader.SetString(Component.ListFiles("/"));
    Files = ReadJSON(Reader);
    Reader.Close();
    Binary = Component.GetFileBinData("/payload.bin");
    If TypeOf(Binary) <> Type("BinaryData") Or Binary.Size() <> {PAYLOAD_SIZE} Then
        Raise "Invalid BinaryData";
    EndIf;
    Binary.Write({literal(root / "binary.bin")});
    EmptyBinary = Component.GetFileBinData("/empty.bin");
    If EmptyBinary.Size() <> 0 Then
        Raise "Invalid empty BinaryData";
    EndIf;
    SavedPath = Component.GetFile("/payload.bin", {literal(root / "downloads" / "nested" / "renamed.bin")});
    Reader = New JSONReader;
    Reader.SetString(Component.Stat("/payload.bin"));
    FileInfo = ReadJSON(Reader);
    Reader.Close();
    If Not FileInfo.exists Or FileInfo.size <> {PAYLOAD_SIZE} Then
        Raise "Invalid Stat result";
    EndIf;
    Reader = New JSONReader;
    Reader.SetString(Component.Stat("/missing.bin"));
    MissingInfo = ReadJSON(Reader);
    Reader.Close();
    If MissingInfo.exists Then
        Raise "Missing file Stat returned exists=true";
    EndIf;
    NoOverwriteFailed = False;
    Try
        Component.GetFile("/payload.bin", SavedPath, True);
    Except
        FailureText = Component.LastError;
        FailureDetails = Component.LastErrorDetails;
        NoOverwriteFailed = StrFind(FailureText, "Save local file") > 0;
    EndTry;
    If Not NoOverwriteFailed Then
        Raise "No-overwrite exception did not expose the component error";
    EndIf;
    Component.Disconnect();
    If Component.LastError <> "" Or Component.LastErrorDetails <> "{{}}" Then
        Raise "Disconnect did not clear component diagnostics";
    EndIf;
    If FailureText = "" Or FailureDetails = "{{}}" Then
        Raise "Diagnostics were not copied before Disconnect";
    EndIf;
    Component.Connect("127.0.0.1", {server.port}, "test", "test-password", {literal(server.fingerprint)});
    LargeBinary = Component.GetFileBinData("/large.bin");
    LargeSize = LargeBinary.Size();
    If LargeSize <> 104857600 Then
        Raise "Invalid 100 MiB BinaryData";
    EndIf;
    LargeBinary = Undefined;
    Component.GetFile("/large.bin", {literal(root / "downloads" / "nested" / "large.bin")});
    Component.MoveFile("/move.bin", "/archive/renamed.bin");
    Component.DeleteFile("/archive/renamed.bin");
    MissingFailed = False;
    Try
        Component.GetFileBinData("/missing.bin");
    Except
        MissingFailed = Component.LastError <> "";
        MissingText = Component.LastError;
        MissingDetails = Component.LastErrorDetails;
    EndTry;
    If Not MissingFailed Then
        Raise "Missing file error was not raised";
    EndIf;
    Version = Component.Version;
    Component.Disconnect();
    If Component.LastError <> "" Or Component.LastErrorDetails <> "{{}}" Then
        Raise "Disconnect did not clear the missing-file error";
    EndIf;
    If MissingText = "" Or MissingDetails = "{{}}" Then
        Raise "Missing-file diagnostics were not copied before Disconnect";
    EndIf;
    MCPResult = New Structure("success,version,fileCount,binarySize,largeBinarySize,savedPath,nativeError", True, Version, Files.Count(), Binary.Size(), LargeSize, SavedPath, MissingText);
Except
    FailureText = Component.LastError;
    If FailureText = "" Then
        FailureText = ErrorDescription();
    EndIf;
    Component.Disconnect();
    Raise FailureText;
EndTry;
'''
            result = rpc(endpoint, "tools/call", {"name": "Execute", "arguments": {"code": code}}, opener)
        if result.get("isError"):
            raise RuntimeError(result)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        assert (root / "binary.bin").read_bytes() == payload(0, PAYLOAD_SIZE)
        assert (root / "downloads" / "nested" / "renamed.bin").read_bytes() == payload(0, PAYLOAD_SIZE)
        with (root / "downloads" / "nested" / "large.bin").open("rb") as stream:
            offset = 0
            while chunk := stream.read(1024 * 1024):
                assert chunk == payload(offset, len(chunk))
                offset += len(chunk)
            assert offset == 104857600
        assert not (remote / "move.bin").exists()
        assert not (remote / "archive" / "renamed.bin").exists()
        print("Real 1C server MCP test passed: Stat, diagnostics copied before Disconnect, no-overwrite, 100 MiB and move/delete")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("endpoint")
    parser.add_argument("package", type=Path)
    parser.add_argument("--temp-root", type=Path)
    parser.add_argument("--publication", type=Path, help="Optional local default.vrd for HTTP Basic credentials (not logged)")
    parser.add_argument("--user", help="HTTP Basic user; password is read from MCP_HTTP_PASSWORD, default empty")
    args = parser.parse_args()
    logging.getLogger("paramiko").setLevel(logging.CRITICAL)
    run(args.endpoint, args.package.resolve(), args.temp_root, args.publication, args.user)
