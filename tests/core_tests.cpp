#include "Utils.h"
#include <iostream>
#include <functional>

namespace {
void check(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
void rejects(const std::function<void()>& action) {
    try { action(); } catch (const sftp::Error&) { return; }
    throw std::runtime_error("Expected a validation error");
}
}
int main() {
    try {
        const std::wstring unicode = L"Отчёт 日本語 \U0001f600.csv";
        check(sftp::wide(sftp::utf8(unicode)) == unicode, "Unicode round trip");
        check(sftp::jsonString("a\"\\\n\t\r\b\f\x01") == "\"a\\\"\\\\\\u000a\\u0009\\u000d\\u0008\\u000c\\u0001\"", "JSON escaping");
        check(sftp::jsonString(sftp::utf8(unicode)) == "\"" + sftp::utf8(unicode) + "\"", "JSON Unicode");
        rejects([] { sftp::wide(std::string("\xc0\xaf", 2)); });
        rejects([] { sftp::utf8(std::wstring(1, static_cast<wchar_t>(0xd800))); });
        check(sftp::localFileName("/exchange/report.csv") == L"report.csv", "Remote basename");
        check(sftp::localFileName(sftp::utf8(L"/обмен/Отчёт.csv")) == L"Отчёт.csv", "Unicode basename");
        for (const auto path : {"/", "/a/..", "/a/.", "/x/CON", "/x/nul.txt", "/x/COM1.csv", "/x/LPT9", "/x/a:b", "/x/a\\b", "/x/a.", "/x/a ", "/x/a\n"})
            rejects([&] { sftp::localFileName(path); });
        check(sftp::localFileName("/x/COM10.txt") == L"COM10.txt", "Non-device filename");
        rejects([] { sftp::validateText(std::string("a\0b", 3), "path"); });
        const std::string fingerprint(43, 'A');
        for (const auto bits : {"255", "256"}) {
            const auto parsed = sftp::parseHostKeyFingerprint(std::string("ssh-ed25519 ") + bits + " " + std::string(43, 'A') + "=");
            check(parsed.fingerprint == fingerprint && parsed.keyType == "ssh-ed25519", "WinSCP SHA-256 fingerprint");
        }
        rejects([&] { sftp::parseHostKeyFingerprint("SHA256:" + fingerprint); });
        check(sftp::parseHostKeyFingerprint("").fingerprint.empty(), "Optional parsed fingerprint");
        for (const auto value : {"ssh-ed25519 255 68:cf:58:fb", "ssh-ed25519 -1 AAA", "ssh-ed25519 0 AAA",
                                 "ssh-ed25519 bits AAA", "ssh-ed25519 255 AAA extra", "unknown 255 AAA",
                                 "ssh-ed25519 255", "MD5:68:cf:58:fb"})
            rejects([&] { sftp::parseHostKeyFingerprint(value); });
        rejects([] { sftp::parseHostKeyFingerprint("ssh-ed25519 255 " + std::string(43, '!')); });
        rejects([] { sftp::parseHostKeyFingerprint("ssh-ed25519 255 " + std::string(42, 'A') + "B"); });
        std::cout << "core_tests passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
