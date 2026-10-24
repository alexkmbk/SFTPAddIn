#include "SftpClient.h"
#include <windows.h>
#include <iostream>
#include <thread>
#ifdef _DEBUG
#include <crtdbg.h>
#endif

namespace {
void check(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
void cycle(int port, const std::string& pin, const std::filesystem::path& directory, int fault) {
    sftp::Client client;
    client.setTimeout(5);
    client.connect("127.0.0.1", port, "test", "test-password", pin);
    client.listFiles("/");
    client.stat("/payload.bin");
    client.getFileBinData("/payload.bin");
    client.getFile("/payload.bin", (directory / "download.bin").wstring());
    client.putFile((directory / "source.bin").wstring(), "/uploads/stress.bin");
    try { client.stat("/denied.bin"); } catch (const sftp::Error&) {}
    if (fault) {
        client.setTimeout(1);
        bool rejected = false;
        try {
            if (fault == 1) client.getFileBinData("/close-stall.bin");
            if (fault == 2) client.putFile((directory / "source.bin").wstring(), "/uploads/close-stall/stress.bin");
            if (fault == 3) client.listFiles("/close-stall");
            if (fault == 4) client.getFileBinData("/close-denied.bin");
        } catch (const sftp::Error& error) {
            rejected = true;
            check(error.connectionLost == (fault != 4), "Close failure session lifetime");
        }
        check(rejected && client.connected() == (fault == 4), "Expected close failure");
    }
    client.disconnect();
    client.setTimeout(5);
    for (int failure = 0; failure < 2; ++failure) {
        auto wrongPin = pin;
        const auto hash = wrongPin.find_last_of(' ') + 1;
        wrongPin[hash] = wrongPin[hash] == 'A' ? 'B' : 'A';
        bool rejected = false;
        try { client.connect("127.0.0.1", port, "test", failure ? "wrong-password" : "test-password", failure ? pin : wrongPin); }
        catch (const sftp::Error&) { rejected = true; }
        check(rejected && !client.connected(), "Failed Connect retained its session");
    }
    // A fresh Client destructor must also release an open session without explicit Disconnect.
    client.connect("127.0.0.1", port, "test", "test-password", pin);
    client.getFileBinData("/empty.bin");
}
}
int wmain(int argc, wchar_t** argv) {
    try {
        check(argc == 4, "Usage: resource_stress port fingerprint output-directory");
#ifndef _DEBUG
        (void)argv;
        throw std::runtime_error("Use a Debug build: exact CRT allocation checks require /MTd");
#else
        _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
        _CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDERR);
        const auto port = std::stoi(argv[1]);
        const auto pin = sftp::utf8(argv[2]);
        const std::filesystem::path directory(argv[3]);
        std::cout << "Checking debug CRT allocations for core, libssh2 and OpenSSL in one executable\n";
        for (int i = 0; i < 5; ++i) cycle(port, pin, directory, 0);
        const auto threadCycle = [&] {
            std::exception_ptr failure;
            std::thread([&] { try { cycle(port, pin, directory, 0); } catch (...) { failure = std::current_exception(); } }).join();
            if (failure) std::rethrow_exception(failure);
        };
        threadCycle();
        DWORD handlesBefore = 0, handlesAfter = 0;
        check(GetProcessHandleCount(GetCurrentProcess(), &handlesBefore) != 0, "Read initial handle count");
        _CrtMemState before{}, after{}, difference{};
        _CrtMemCheckpoint(&before);
        const auto setting = [](const wchar_t* name, int fallback) {
            wchar_t text[16]{};
            return GetEnvironmentVariableW(name, text, 16) ? std::stoi(text) : fallback;
        };
        const int normalCycles = setting(L"SFTP_STRESS_CYCLES", 50);
        const int faultyCycles = setting(L"SFTP_STRESS_FAULTS", 4);
        const int threadedCycles = 20;
        for (int i = 0; i < normalCycles; ++i) cycle(port, pin, directory, 0);
        for (int i = 0; i < threadedCycles; ++i) threadCycle();
        for (int fault = 1; fault <= 4; ++fault)
            for (int i = 0; i < faultyCycles; ++i) cycle(port, pin, directory, fault);
        _CrtMemCheckpoint(&after);
        _CrtMemDifference(&difference, &before, &after);
        check(GetProcessHandleCount(GetCurrentProcess(), &handlesAfter) != 0, "Read final handle count");
        const auto blocks = static_cast<long long>(after.lCounts[_NORMAL_BLOCK]) - static_cast<long long>(before.lCounts[_NORMAL_BLOCK]);
        const auto bytes = static_cast<long long>(after.lSizes[_NORMAL_BLOCK]) - static_cast<long long>(before.lSizes[_NORMAL_BLOCK]);
        std::cout << "Debug CRT live allocations delta: " << blocks << " blocks, " << bytes << " bytes; Windows handles: " << handlesBefore << " -> " << handlesAfter << '\n';
        if (blocks > 0 || bytes > 0) _CrtMemDumpStatistics(&difference);
        check(blocks <= 0 && bytes <= 0, "Core or dependency retained allocations after stress cycles");
        check(handlesAfter == handlesBefore, "Stress cycles leaked Windows handles");
        std::cout << "resource_stress passed: " << (normalCycles + threadedCycles + faultyCycles * 4)
            << " cycles, " << (faultyCycles * 3) << " delayed closes, no live allocation or handle growth\n";
        return 0;
#endif
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
