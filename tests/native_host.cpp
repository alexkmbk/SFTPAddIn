#include "ComponentBase.h"
#include "AddInDefBase.h"
#include "IMemoryManager.h"
#include <windows.h>
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <string>
#include <vector>

namespace {
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
struct Memory final : IMemoryManager {
    std::set<void*> allocations;
    bool failNext = false;
    bool ADDIN_API AllocMemory(void** pointer, unsigned long size) override {
        *pointer = nullptr;
        if (failNext) { failNext = false; return false; }
        *pointer = std::malloc(size ? size : 1);
        if (*pointer) allocations.insert(*pointer);
        return *pointer != nullptr;
    }
    void ADDIN_API FreeMemory(void** pointer) override {
        if (!pointer || !*pointer) return;
        if (!allocations.erase(*pointer)) std::abort();
        std::free(*pointer); *pointer = nullptr;
    }
    ~Memory() { if (!allocations.empty()) std::abort(); }
};
struct Platform final : IAddInDefBase {
    std::wstring error;
    bool ADDIN_API AddError(unsigned short, const WCHAR_T*, const WCHAR_T* description, long) override { error = description; return true; }
    bool ADDIN_API Read(WCHAR_T*, tVariant*, long*, WCHAR_T**) override { return false; }
    bool ADDIN_API Write(WCHAR_T*, tVariant*) override { return false; }
    bool ADDIN_API RegisterProfileAs(WCHAR_T*) override { return true; }
    bool ADDIN_API SetEventBufferDepth(long) override { return false; }
    long ADDIN_API GetEventBufferDepth() override { return 0; }
    bool ADDIN_API ExternalEvent(WCHAR_T*, WCHAR_T*, WCHAR_T*) override { return false; }
    void ADDIN_API CleanEventBuffer() override {}
    bool ADDIN_API SetStatusLine(WCHAR_T*) override { return false; }
    void ADDIN_API ResetStatusLine() override {}
};
struct Value {
    tVariant value{};
    Memory* memory;
    explicit Value(Memory& owner) : memory(&owner) {}
    Value(Value&& other) noexcept : value(other.value), memory(other.memory) { tVarInit(&other.value); }
    ~Value() {
        if (value.vt == VTYPE_PWSTR || value.vt == VTYPE_BLOB) {
            void* pointer = value.vt == VTYPE_PWSTR ? static_cast<void*>(value.pwstrVal) : static_cast<void*>(value.pstrVal);
            memory->FreeMemory(&pointer);
        }
    }
    std::wstring text() const {
        check(value.vt == VTYPE_PWSTR, "Expected a string result");
        return std::wstring(value.pwstrVal, value.wstrLen);
    }
};
tVariant text(const wchar_t* string) {
    tVariant result{}; result.vt = VTYPE_PWSTR; result.pwstrVal = const_cast<wchar_t*>(string);
    result.wstrLen = static_cast<std::uint32_t>(std::wcslen(string)); return result;
}
tVariant number(double value) { tVariant result{}; result.vt = VTYPE_R8; result.dblVal = value; return result; }
tVariant flag(bool value) { tVariant result{}; result.vt = VTYPE_BOOL; result.bVal = value; return result; }
struct Host {
    HMODULE module = nullptr;
    IComponentBase* object = nullptr;
    DestroyObjectPtr destroy = nullptr;
    Memory memory;
    Platform platform;
    explicit Host(const wchar_t* dll) {
        module = LoadLibraryW(dll); check(module != nullptr, "LoadLibrary failed");
        auto names = reinterpret_cast<GetClassNamesPtr>(GetProcAddress(module, "GetClassNames"));
        auto create = reinterpret_cast<GetClassObjectPtr>(GetProcAddress(module, "GetClassObject"));
        destroy = reinterpret_cast<DestroyObjectPtr>(GetProcAddress(module, "DestroyObject"));
        auto capabilities = reinterpret_cast<SetPlatformCapabilitiesPtr>(GetProcAddress(module, "SetPlatformCapabilities"));
        check(names && create && destroy && capabilities, "Missing Native API export");
        check(std::wcscmp(names(), L"SFTP") == 0, "Class names");
        check(create(L"Unknown", &object) == 0 && object == nullptr, "Unknown class");
        check(create(nullptr, &object) == 0, "Null class");
        check(create(L"SFTP", nullptr) == 0, "Null output");
        check(create(L"SFTP", &object) != 0 && object, "Create instance");
        check(create(L"SFTP", &object) == 0, "Existing instance");
        check(capabilities(eAppCapabilities1) == eAppCapabilities1, "Capabilities");
        check(object->Init(&platform) && object->setMemManager(&memory), "Initialize");
    }
    ~Host() {
        if (object) { object->Done(); destroy(&object); }
        if (module) FreeLibrary(module);
    }
    Value property(const wchar_t* name) {
        Value result(memory);
        check(object->GetPropVal(object->FindProp(name), &result.value), "Get property failed");
        return result;
    }
    Value invoke(const wchar_t* name, std::initializer_list<tVariant> args = {}) {
        Value result(memory);
        std::vector<tVariant> arguments(args);
        if (!object->CallAsFunc(object->FindMethod(name), &result.value, arguments.data(), static_cast<long>(arguments.size()))) {
            std::wcerr << platform.error << L'\n'; throw std::runtime_error("Native API call failed");
        }
        return result;
    }
    void fails(const wchar_t* name, std::initializer_list<tVariant> args = {}) {
        Value result(memory); std::vector<tVariant> arguments(args); platform.error.clear();
        check(!object->CallAsFunc(object->FindMethod(name), &result.value, arguments.data(), static_cast<long>(arguments.size())), "Expected operation to fail");
        check(!platform.error.empty(), "Error was not reported to 1C");
        check(!property(L"LastError").text().empty(), "LastError missing");
        check(property(L"LastErrorDetails").text().find(L"\"code\":") != std::wstring::npos, "Error details missing");
        check(result.value.vt == VTYPE_EMPTY, "Failed call returned a value");
    }
};
void apiTests(Host& host) {
    auto object = host.object;
    check(!host.property(L"Connected").value.bVal, "Initial connection state");
    check(host.property(L"Version").text() == L"0.2.0", "Version");
    check(object->FindMethod(L"getfile") == object->FindMethod(L"ПолучитьФайл"), "Method aliases");
    check(object->FindMethod(nullptr) == -1 && object->FindProp(nullptr) == -1, "Null name");
    check(object->FindMethod(L"ClearError") == -1 && object->FindMethod(L"ОчиститьОшибку") == -1, "Unexpected ClearError method");
    check(object->FindProp(L"LastErrorCode") == -1 && object->FindProp(L"КодПоследнейОшибки") == -1, "Unexpected LastErrorCode property");
    check(!object->GetMethodName(-1, 0) && !object->GetPropName(-1, 0), "Negative index");
    check(!object->GetMethodName(0, 2) && !object->GetPropName(0, 2), "Invalid alias");
    for (long i = 0; i < object->GetNMethods(); ++i) for (long alias = 0; alias <= 1; ++alias) {
        auto name = object->GetMethodName(i, alias); check(name && object->FindMethod(name) == i, "Method lookup");
        void* pointer = const_cast<WCHAR_T*>(name); host.memory.FreeMemory(&pointer);
    }
    for (long i = 0; i < object->GetNProps(); ++i) for (long alias = 0; alias <= 1; ++alias) {
        auto name = object->GetPropName(i, alias); check(name && object->FindProp(name) == i, "Property lookup");
        void* pointer = const_cast<WCHAR_T*>(name); host.memory.FreeMemory(&pointer);
    }
    WCHAR_T* extension = nullptr; check(object->RegisterExtensionAs(&extension), "Extension name");
    check(std::wcscmp(extension, L"SFTP") == 0, "Extension value");
    void* allocation = extension; host.memory.FreeMemory(&allocation);
    { Value value(host.memory); check(object->GetParamDefValue(0, 4, &value.value) && value.text().empty(), "Optional fingerprint"); }
    for (const auto name : {L"GetFile", L"MoveFile", L"Stat", L"PutFile", L"PutFiles"}) {
        Value value(host.memory); const auto method = object->FindMethod(name);
        check(object->GetParamDefValue(method, object->GetNParams(method) - 1, &value.value) &&
            value.value.vt == VTYPE_BOOL && !value.value.bVal, "Optional boolean default");
    }
    auto timeout = number(2); check(object->SetPropVal(object->FindProp(L"Timeout"), &timeout), "Set timeout");
    timeout = number(1.5); check(!object->SetPropVal(object->FindProp(L"Timeout"), &timeout), "Fractional timeout accepted");
    timeout = number(0); check(!object->SetPropVal(object->FindProp(L"Timeout"), &timeout), "Zero timeout accepted");
    host.fails(L"GetFileBinData", {text(L"/a")});
    host.fails(L"GetFile");
    host.fails(L"Connect", {text(L"localhost"), number(22.5), text(L"test"), text(L"password")});
    host.memory.failNext = true;
    { Value value(host.memory); check(!object->GetPropVal(object->FindProp(L"Version"), &value.value), "Allocation failure not handled"); }
    const auto previousError = host.property(L"LastError").text();
    const auto previousDetails = host.property(L"LastErrorDetails").text();
    host.property(L"Version"); host.property(L"Connected");
    check(host.property(L"LastError").text() == previousError && !previousError.empty() &&
        host.property(L"LastErrorDetails").text() == previousDetails, "Property reads erased diagnostics");
    host.invoke(L"Disconnect");
    check(host.property(L"LastError").text().empty() && host.property(L"LastErrorDetails").text() == L"{}", "Disconnect did not clear diagnostics");
    host.fails(L"GetFileBinData", {text(L"/a")});
    timeout = number(2); check(object->SetPropVal(object->FindProp(L"Timeout"), &timeout), "Set timeout");
    check(host.property(L"LastError").text().empty() && host.property(L"LastErrorDetails").text() == L"{}", "Timeout did not clear diagnostics");
    check(object->CallAsProc(object->FindMethod(L"Disconnect"), nullptr, 0), "Procedure call");
}
#include "native_memory_tests.inc"

void expectPayload(const Value& result, std::size_t size) {
    check(result.value.vt == VTYPE_BLOB && result.value.strLen == size, "Binary data length/type");
    for (std::size_t i = 0; i < size; ++i)
        if (static_cast<unsigned char>(result.value.pstrVal[i]) != i % 251) throw std::runtime_error("Binary payload corrupted");
}
void saveJSON(const std::filesystem::path& path, const std::wstring& value) {
    const int length = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    std::string encoded(length, '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), encoded.data(), length, nullptr, nullptr);
    std::ofstream stream(path, std::ios::binary); stream << encoded;
}
void unsupportedExtension(Host& host, int port, const wchar_t* fingerprint) {
    host.invoke(L"Connect", {text(L"127.0.0.1"), number(port), text(L"test"), text(L"test-password"), text(fingerprint)});
    host.fails(L"MoveFile", {text(L"/unsupported.bin"), text(L"/archive/unsupported.bin"), flag(true)});
    const auto details = host.property(L"LastErrorDetails").text();
    check(details.find(L"\"sftpCode\":8") != std::wstring::npos &&
        details.find(L"\"connectionLost\":false") != std::wstring::npos &&
        details.find(L"\"outcomeUnknown\":false") != std::wstring::npos, "Unadvertised extension error semantics");
    check(host.property(L"Connected").value.bVal, "Unadvertised extension closed a usable connection");
    host.invoke(L"Stat", {text(L"/unsupported.bin")});
    host.invoke(L"Disconnect");
}
void uploadTests(Host& host, int port, const wchar_t* fingerprint, const std::filesystem::path& output) {
    const auto source = output / "upload-source";
    const auto normal = source / "normal.bin";
    check(host.invoke(L"PutFile", {text(normal.c_str()), text(L"/uploads/normal.bin")}).value.bVal, "PutFile result");
    expectPayload(host.invoke(L"GetFileBinData", {text(L"/uploads/normal.bin")}), 300123);
    check(!host.invoke(L"PutFile", {text(normal.c_str()), text(L"/uploads/normal.bin"), flag(true), flag(true)}).value.bVal, "NewerOnly equal timestamp skip");
    check(std::filesystem::exists(normal), "Skipped source was deleted");
    {
        HANDLE file = CreateFileW(normal.c_str(), FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        check(file != INVALID_HANDLE_VALUE, "Open source to update timestamp");
        ULARGE_INTEGER time{}; time.QuadPart = 116444736000000000ULL + 1700000001ULL * 10000000ULL;
        FILETIME modified{time.LowPart, time.HighPart};
        const bool changed = SetFileTime(file, nullptr, nullptr, &modified) != 0; CloseHandle(file);
        check(changed, "Set source modification time");
    }
    check(host.invoke(L"PutFile", {text(normal.c_str()), text(L"/uploads/normal.bin"), flag(false), flag(true)}).value.bVal, "NewerOnly newer source");
    check(host.invoke(L"Stat", {text(L"/uploads/normal.bin")}).text().find(L"\"modifiedTime\":1700000001") != std::wstring::npos, "Preserved upload timestamp");
    for (const auto name : {L"empty.bin", L"Отчёт.bin"}) {
        const auto path = source / name; const auto target = std::wstring(L"/uploads/") + name;
        host.invoke(L"PutFile", {text(path.c_str()), text(target.c_str())});
    }
    const auto large = output / L"новая папка" / "nested" / "large.bin";
    host.invoke(L"PutFile", {text(large.c_str()), text(L"/uploads/large.bin")});
    const auto deleted = source / "delete.bin";
    host.invoke(L"PutFile", {text(deleted.c_str()), text(L"/uploads/delete.bin"), flag(true)});
    check(!std::filesystem::exists(deleted), "DeleteSource did not remove uploaded source");
    for (const auto target : {L"/uploads/write-fail/target.bin", L"/uploads/setstat-fail/target.bin", L"/uploads/rename-fail.bin", L"/uploads/no-replace.bin", L"/uploads/unknown-time.bin"}) {
        host.fails(L"PutFile", {text(normal.c_str()), text(target), flag(true), flag(std::wstring(target) == L"/uploads/unknown-time.bin")});
        check(std::filesystem::exists(normal), "Failed upload deleted its source");
        check(host.property(L"LastErrorDetails").text().find(L"\"transferCompleted\":false") != std::wstring::npos, "Failed upload diagnostic");
    }
    const auto readonly = source / "readonly.bin";
    check(SetFileAttributesW(readonly.c_str(), FILE_ATTRIBUTE_READONLY) != 0, "Set readonly source");
    host.fails(L"PutFile", {text(readonly.c_str()), text(L"/uploads/readonly.bin"), flag(true)});
    const auto deletionError = host.property(L"LastErrorDetails").text();
    SetFileAttributesW(readonly.c_str(), FILE_ATTRIBUTE_NORMAL);
    saveJSON(output / "upload-delete-error.json", deletionError);
    check(deletionError.find(L"\"transferCompleted\":true") != std::wstring::npos, "Upload completed before local delete error");
    const auto batch = output / "batch-source";
    host.fails(L"PutFiles", {text(batch.c_str()), text(L"/uploads/batch"), flag(true), flag(true)});
    saveJSON(output / "upload-batch-error.json", host.property(L"LastErrorDetails").text());
    const auto all = output / "all-source";
    saveJSON(output / "upload-batch-result.json", host.invoke(L"PutFiles", {text(all.c_str()), text(L"/uploads/all")}).text());
    const auto empty = output / "empty-source";
    check(host.invoke(L"PutFiles", {text(empty.c_str()), text(L"/uploads")}).text().find(L"\"uploaded\":[]") != std::wstring::npos, "Empty batch");
    host.fails(L"PutFiles", {text(empty.c_str()), text(L"/missing-upload-directory")});
    host.fails(L"PutFile", {text(normal.c_str()), text(L"/uploads/uncertain-upload.bin"), flag(true)});
    saveJSON(output / "upload-uncertain.json", host.property(L"LastErrorDetails").text());
    check(std::filesystem::exists(normal), "Unknown upload outcome deleted source");
    host.invoke(L"Connect", {text(L"127.0.0.1"), number(port), text(L"test"), text(L"test-password"), text(fingerprint)});
    expectPayload(host.invoke(L"GetFileBinData", {text(L"/uploads/uncertain-upload.bin")}), 300123);
}
void networkMemoryTests(Host& host) {
    for (int iteration = 0; iteration < 250; ++iteration) {
        for (const auto name : {L"ListFiles", L"Stat", L"GetFileBinData"}) {
            tVariant argument = text(std::wstring(name) == L"ListFiles" ? L"/archive" : L"/payload.bin");
            check(host.object->CallAsProc(host.object->FindMethod(name), &argument, 1), "Discarded network result failed");
            check(host.memory.allocations.empty(), "CallAsProc retained a network result");
            host.memory.failNext = true;
            { host.fails(name, {argument}); }
            check(!host.memory.failNext && host.memory.allocations.empty(), "Network result allocation failure leaked platform memory");
            check(host.property(L"Connected").value.bVal, "Allocation failure destroyed a usable connection");
        }
    }
}
void integration(Host& host, int port, const wchar_t* fingerprint, const std::filesystem::path& output) {
    auto connect = [&](const wchar_t* pin, const wchar_t* password = L"test-password") {
        return host.invoke(L"Connect", {text(L"127.0.0.1"), number(port), text(L"test"), text(password), text(pin)});
    };
    std::wstring wrongFingerprint(fingerprint);
    const auto hashOffset = wrongFingerprint.find_last_of(L' ') + 1;
    wrongFingerprint[hashOffset] = wrongFingerprint[hashOffset] == L'A' ? L'B' : L'A';
    host.fails(L"Connect", {text(L"127.0.0.1"), number(port), text(L"test"), text(L"test-password"), text(wrongFingerprint.c_str())});
    check(!host.property(L"Connected").value.bVal, "Mismatch left session connected");
    host.fails(L"Connect", {text(L"127.0.0.1"), number(port), text(L"test"), text(L"wrong"), text(fingerprint)});
    const auto hash = std::wstring(fingerprint).substr(hashOffset);
    const auto shortPin = L"SHA256:" + hash;
    host.fails(L"Connect", {text(L"127.0.0.1"), number(port), text(L"test"), text(L"test-password"), text(shortPin.c_str())});
    const auto wrongType = L"ssh-ed25519 255 " + hash;
    host.fails(L"Connect", {text(L"127.0.0.1"), number(port), text(L"test"), text(L"test-password"), text(wrongType.c_str())});
    check(!host.property(L"Connected").value.bVal, "Unavailable key type must reject connection");
    const auto winscp = L"ssh-rsa 2048 " + hash;
    connect(winscp.c_str());
    check(host.property(L"HostKeyFingerprint").text() == fingerprint, "WinSCP pin returns full fingerprint");
    const auto wrongWinScp = L"ssh-rsa 2048 " + wrongFingerprint.substr(hashOffset);
    host.fails(L"Connect", {text(L"127.0.0.1"), number(port), text(L"test"), text(L"test-password"), text(wrongWinScp.c_str())});
    connect(fingerprint);
    check(host.property(L"Connected").value.bVal, "Session not connected");
    check(host.property(L"HostKeyFingerprint").text() == fingerprint, "Actual fingerprint");
    networkMemoryTests(host);
    const auto listing = host.invoke(L"ListFiles", {text(L"/")}).text();
    check(listing.find(L"Отчёт") != std::wstring::npos && listing.find(L"\\\"") != std::wstring::npos &&
        listing.find(L"\\u000a") != std::wstring::npos, "JSON names/escaping");
    { std::ofstream stream(output / "listing.json", std::ios::binary); const int length = WideCharToMultiByte(CP_UTF8, 0, listing.data(), static_cast<int>(listing.size()), nullptr, 0, nullptr, nullptr);
      std::string encoded(length, '\0'); WideCharToMultiByte(CP_UTF8, 0, listing.data(), static_cast<int>(listing.size()), encoded.data(), length, nullptr, nullptr); stream << encoded; }
    expectPayload(host.invoke(L"GetFileBinData", {text(L"/payload.bin")}), 300123);
    expectPayload(host.invoke(L"GetFileBinData", {text(L"/empty.bin")}), 0);
    expectPayload(host.invoke(L"GetFileBinData", {text(L"/Отчёт.bin")}), 300123);
    expectPayload(host.invoke(L"GetFileBinData", {text(L"/large.bin")}), 100 * 1024 * 1024);
    host.fails(L"GetFileBinData", {text(L"/missing.bin")});
    host.fails(L"GetFileBinData", {text(L"/archive")});
    const auto directory = output / L"новая папка" / L"nested";
    const auto payloadPath = directory / L"payload.bin";
    auto result = host.invoke(L"GetFile", {text(L"/payload.bin"), text(payloadPath.c_str())}).text();
    check(std::filesystem::path(result) == directory / L"payload.bin", "Saved path");
    { std::ofstream stream(directory / L"payload.bin", std::ios::binary); stream << "old"; }
    host.fails(L"GetFile", {text(L"/payload.bin"), text(payloadPath.c_str()), flag(true)});
    check(std::filesystem::file_size(payloadPath) == 3, "No-overwrite changed existing file");
    check(host.property(L"LastErrorDetails").text().find(L"\"systemCode\":") != std::wstring::npos, "Windows error code missing");
    host.invoke(L"GetFile", {text(L"/payload.bin"), text(payloadPath.c_str())});
    check(std::filesystem::file_size(directory / L"payload.bin") == 300123, "Overwrite failed");
    host.invoke(L"GetFile", {text(L"/Отчёт.bin"), text((directory / L"Отчёт.bin").c_str())});
    host.invoke(L"GetFile", {text(L"/large.bin"), text((directory / L"large.bin").c_str())});
    host.invoke(L"GetFile", {text(L"/payload.bin"), text((directory / L"renamed.bin").c_str()), flag(true)});
    check(std::filesystem::file_size(directory / L"renamed.bin") == 300123, "Local rename");
    host.fails(L"GetFile", {text(L"/race.bin"), text((directory / L"race.bin").c_str()), flag(true)});
    { std::ifstream stream(directory / L"race.bin", std::ios::binary); std::string data((std::istreambuf_iterator<char>(stream)), {}); check(data == "concurrent", "No-overwrite race lost existing file"); }
    check(std::filesystem::file_size(directory / L"large.bin") == 100 * 1024 * 1024, "Large disk download");
    { std::ofstream stream(directory / L"broken.bin", std::ios::binary); stream << "keep"; }
    host.fails(L"GetFile", {text(L"/broken.bin"), text((directory / L"broken.bin").c_str())});
    { std::ifstream stream(directory / L"broken.bin", std::ios::binary); std::string data((std::istreambuf_iterator<char>(stream)), {}); check(data == "keep", "Failed download destroyed old file"); }
    for (const auto& entry : std::filesystem::directory_iterator(directory))
        check(entry.path().filename().wstring().find(L".sftp-") != 0, "Temporary file leaked");
    host.fails(L"GetFile", {text(L"/payload.bin"), text((directory / L"a:b").c_str())});
    host.fails(L"GetFile", {text(L"/payload.bin"), text(L"relative.bin")});
    host.fails(L"GetFile", {text(L"/payload.bin"), text(payloadPath.c_str()), number(1)});
    auto statResult = host.invoke(L"Stat", {text(L"/payload.bin")}).text();
    saveJSON(output / "stat.json", statResult);
    check(statResult.find(L"\"exists\":true") != std::wstring::npos && statResult.find(L"\"size\":300123") != std::wstring::npos, "Stat file");
    check(host.invoke(L"Stat", {text(L"/archive")}).text().find(L"\"type\":\"directory\"") != std::wstring::npos, "Stat directory");
    check(host.invoke(L"Stat", {text(L"/missing.bin")}).text().find(L"\"exists\":false") != std::wstring::npos, "Missing Stat");
    check(host.invoke(L"Stat", {text(L"/link.bin")}).text().find(L"\"type\":\"symlink\"") != std::wstring::npos, "lstat link");
    check(host.invoke(L"Stat", {text(L"/link.bin"), flag(true)}).text().find(L"\"type\":\"file\"") != std::wstring::npos, "Follow link");
    check(host.invoke(L"Stat", {text(L"/broken-link")}).text().find(L"\"exists\":true") != std::wstring::npos, "Broken link exists");
    check(host.invoke(L"Stat", {text(L"/broken-link"), flag(true)}).text().find(L"\"exists\":false") != std::wstring::npos, "Broken link target");
    check(host.invoke(L"Stat", {text(L"/unknown")}).text().find(L"\"size\":null") != std::wstring::npos, "Missing attributes");
    host.fails(L"Stat", {text(L"/denied.bin")});
    const auto denied = host.property(L"LastErrorDetails").text();
    saveJSON(output / "error.json", denied);
    check(denied.find(L"\"operation\":\"Stat\"") != std::wstring::npos && denied.find(L"\"sftpCode\":3") != std::wstring::npos, "Stat permission error details");
    host.invoke(L"Stat", {text(L"/payload.bin")});
    check(host.property(L"LastError").text().empty(), "Success did not clear error");
    host.fails(L"MoveFile", {text(L"/collision.bin"), text(L"/archive/collision.bin")});
    host.invoke(L"MoveFile", {text(L"/move.bin"), text(L"/archive/renamed.bin")});
    host.invoke(L"DeleteFile", {text(L"/archive/renamed.bin")});
    host.fails(L"GetFileBinData", {text(L"/archive/renamed.bin")});
    host.invoke(L"MoveFile", {text(L"/replace.bin"), text(L"/archive/replace.bin"), flag(true)});
    host.fails(L"MoveFile", {text(L"/unsupported.bin"), text(L"/archive/unsupported.bin"), flag(true)});
    check(host.property(L"Connected").value.bVal, "Unsupported rename lost connection");
    uploadTests(host, port, fingerprint, output);
    host.fails(L"DeleteFile", {text(L"/uncertain.bin")});
    const auto uncertain = host.property(L"LastErrorDetails").text();
    saveJSON(output / "uncertain.json", uncertain);
    check(uncertain.find(L"\"outcomeUnknown\":true") != std::wstring::npos, "Unknown mutation outcome not reported");
    host.invoke(L"Disconnect");
    check(host.property(L"LastErrorDetails").text() == L"{}" &&
        uncertain.find(L"\"outcomeUnknown\":true") != std::wstring::npos, "Copy diagnostics before Disconnect");
    connect(fingerprint);
    check(host.invoke(L"Stat", {text(L"/uncertain.bin")}).text().find(L"\"exists\":false") != std::wstring::npos, "Server did not apply uncertain delete");
    host.invoke(L"Disconnect");
    host.invoke(L"Connect", {text(L"127.0.0.1"), number(port), text(L"test"), text(L"test-password")});
    expectPayload(host.invoke(L"GetFileBinData", {text(L"/empty.bin")}), 0);
    host.invoke(L"Disconnect");
    connect(L"");
    host.fails(L"GetFileBinData", {text(L"/stall.bin")});
    check(!host.property(L"Connected").value.bVal, "Timed out connection was not invalidated");
    connect(fingerprint);
    expectPayload(host.invoke(L"GetFileBinData", {text(L"/empty.bin")}), 0);
    host.invoke(L"Disconnect");
}
}
std::wstring testEnvironment(const wchar_t* name) {
    const auto size = GetEnvironmentVariableW(name, nullptr, 0);
    check(size != 0, "Missing SFTP test environment variable");
    std::wstring value(size, L'\0');
    const auto length = GetEnvironmentVariableW(name, value.data(), size);
    check(length > 0 && length < size, "Cannot read SFTP test environment variable");
    value.resize(length); return value;
}
int wmain(int argc, wchar_t** argv) {
    try {
        check(argc == 2 || argc == 5 || argc == 6, "Usage: native_host DLL [port fingerprint output-directory [no-posix]]");
        Host host(argv[1]);
        apiTests(host);
        nativeMemoryTests(host);
        if (argc == 5) integration(host, std::stoi(argv[2]), argv[3], argv[4]);
        if (argc == 6 && std::wstring(argv[5]) == L"upload-smoke") {
            const auto address = testEnvironment(L"SFTP_TEST_HOST");
            const auto user = testEnvironment(L"SFTP_TEST_USER");
            auto password = testEnvironment(L"SFTP_TEST_PASSWORD");
            const auto directory = testEnvironment(L"SFTP_TEST_REMOTE");
            host.invoke(L"Connect", {text(address.c_str()), number(std::stoi(argv[2])), text(user.c_str()), text(password.c_str()), text(argv[3])});
            SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
            const auto single = std::filesystem::path(argv[4]) / "single.bin";
            const auto remote = directory + L"/single.bin";
            check(host.invoke(L"PutFile", {text(single.c_str()), text(remote.c_str()), flag(false), flag(true)}).value.bVal, "OpenSSH upload new file");
            check(!host.invoke(L"PutFile", {text(single.c_str()), text(remote.c_str()), flag(true), flag(true)}).value.bVal, "OpenSSH newer-only skip");
            check(std::filesystem::exists(single), "OpenSSH skipped upload deleted its source");
            host.invoke(L"PutFile", {text(single.c_str()), text(remote.c_str())});
            const auto batch = std::filesystem::path(argv[4]) / "batch";
            saveJSON(std::filesystem::path(argv[4]) / "result.json",
                host.invoke(L"PutFiles", {text(batch.c_str()), text(directory.c_str()), flag(true), flag(true)}).text());
            host.invoke(L"Disconnect");
        } else if (argc == 6 && std::wstring(argv[5]) == L"ed25519") {
            const auto fullPin = std::wstring(argv[3]);
            const auto hash = fullPin.substr(fullPin.find_last_of(L' ') + 1);
            for (const auto bits : {L"255", L"256"}) {
                const auto pin = std::wstring(L"ssh-ed25519 ") + bits + L" " + hash + L"=";
                host.invoke(L"Connect", {text(L"127.0.0.1"), number(std::stoi(argv[2])), text(L"test"), text(L"test-password"), text(pin.c_str())});
                check(host.property(L"HostKeyFingerprint").text() == argv[3], "Ed25519 WinSCP fingerprint");
                host.invoke(L"Disconnect");
            }
            const auto wrongType = L"ssh-rsa 2048 " + hash;
            host.fails(L"Connect", {text(L"127.0.0.1"), number(std::stoi(argv[2])), text(L"test"), text(L"test-password"), text(wrongType.c_str())});
            check(!host.property(L"Connected").value.bVal, "Unavailable RSA key must reject connection");
            host.invoke(L"Connect", {text(L"127.0.0.1"), number(std::stoi(argv[2])), text(L"test"), text(L"test-password")});
            const auto ecdsaPin = host.property(L"HostKeyFingerprint").text();
            check(ecdsaPin.find(L"ecdsa-sha2-nistp256 256 ") == 0, "Unpinned ECDSA full fingerprint");
            host.invoke(L"Disconnect");
            host.invoke(L"Connect", {text(L"127.0.0.1"), number(std::stoi(argv[2])), text(L"test"), text(L"test-password"), text(ecdsaPin.c_str())});
            check(host.property(L"HostKeyFingerprint").text() == ecdsaPin, "Returned fingerprint can be reused");
            host.invoke(L"Disconnect");
        } else if (argc == 6) unsupportedExtension(host, std::stoi(argv[2]), argv[3]);
        std::cout << "native_host passed" << (argc == 5 ? " including SFTP integration" : "") << '\n';
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
