#include "Utils.h"
#include <windows.h>
#include <algorithm>
#include <limits>
#include <sstream>

namespace sftp {
std::string UploadReport::json(bool details) const {
    const auto array = [](const std::vector<std::string>& names) {
        std::string result = "[";
        for (const auto& name : names) { if (result.size() > 1) result += ','; result += jsonString(name); }
        return result + "]";
    };
    const auto result = "{\"uploaded\":" + array(uploaded) + ",\"skipped\":" + array(skipped) +
        ",\"pending\":" + array(pending);
    if (!details) return result + "}";
    return result + ",\"failedFile\":" + jsonString(failedFile) +
        ",\"localPath\":" + jsonString(localPath) + ",\"remotePath\":" + jsonString(remotePath) +
        ",\"temporaryPath\":" + jsonString(temporaryPath) +
        ",\"transferCompleted\":" + (transferCompleted ? "true" : "false") +
        ",\"sourceDeleted\":" + (sourceDeleted ? "true" : "false") + "}";
}
std::string utf8(std::wstring_view value) {
    if (value.empty()) return {};
    if (value.size() > INT_MAX) throw Error(ErrorCode::InvalidArgument, "String is too long");
    const int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (!length) throw Error(ErrorCode::InvalidArgument, "Invalid UTF-16 string");
    std::string result(length, '\0');
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), result.data(), length, nullptr, nullptr))
        throw Error(ErrorCode::InvalidArgument, "UTF-16 conversion failed");
    return result;
}
std::wstring wide(std::string_view value) {
    if (value.empty()) return {};
    if (value.size() > INT_MAX) throw Error(ErrorCode::InvalidArgument, "String is too long");
    const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0);
    if (!length) throw Error(ErrorCode::InvalidArgument, "Invalid UTF-8 received from server");
    std::wstring result(length, L'\0');
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), result.data(), length))
        throw Error(ErrorCode::InvalidArgument, "UTF-8 conversion failed");
    return result;
}
std::string jsonString(std::string_view value) {
    // Validate UTF-8; never silently corrupt a server-side filename.
    wide(value);
    constexpr char hex[] = "0123456789abcdef";
    std::string result = "\"";
    for (const unsigned char ch : value) {
        if (ch == '"' || ch == '\\') { result += '\\'; result += static_cast<char>(ch); }
        else if (ch < 0x20) {
            result += "\\u00"; result += hex[ch >> 4]; result += hex[ch & 15];
        } else result += static_cast<char>(ch);
    }
    result += '"';
    return result;
}
namespace {
std::string normalizeSha256Hash(std::string_view value) {
    std::string hash(value);
    if (hash.size() == 44 && hash.back() == '=') hash.pop_back();
    const auto base64 = [](char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') || c == '+' || c == '/';
    };
    if (hash.size() != 43 || !std::all_of(hash.begin(), hash.end(), base64))
        throw Error(ErrorCode::InvalidArgument, "Invalid SHA-256 host key fingerprint");
    // A SHA-256 digest has 256 bits; the final Base64 sextet has two zero bits.
    constexpr std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if ((alphabet.find(hash.back()) & 3) != 0)
        throw Error(ErrorCode::InvalidArgument, "Invalid SHA-256 Base64 padding bits");
    return hash;
}
}
ExpectedHostKey parseHostKeyFingerprint(std::string_view value) {
    if (value.empty()) return {};
    std::istringstream input{std::string(value)};
    std::string type, bits, hash, extra;
    if (!(input >> type >> bits >> hash) || (input >> extra))
        throw Error(ErrorCode::InvalidArgument, "Expected WinSCP SHA-256 fingerprint: key-type bits base64");
    if (type != "ssh-ed25519" && type != "ssh-rsa" && type != "ssh-dss" &&
        type != "ecdsa-sha2-nistp256" && type != "ecdsa-sha2-nistp384" && type != "ecdsa-sha2-nistp521")
        throw Error(ErrorCode::InvalidArgument, "Unsupported host key type in WinSCP fingerprint");
    if (bits.empty() || bits.front() == '0' || bits.size() > 6 ||
        !std::all_of(bits.begin(), bits.end(), [](char c) { return c >= '0' && c <= '9'; }))
        throw Error(ErrorCode::InvalidArgument, "Invalid key size in WinSCP fingerprint");
    return {normalizeSha256Hash(hash), type};
}
void validateText(std::string_view text, const char* label, bool allowEmpty) {
    if ((!allowEmpty && text.empty()) || text.find('\0') != std::string_view::npos || text.size() > UINT_MAX)
        throw Error(ErrorCode::InvalidArgument, std::string("Invalid ") + label);
    wide(text);
}
std::string joinRemote(std::string_view directory, std::string_view name) {
    std::string result(directory);
    if (result.empty() || result.back() != '/') result += '/';
    result += name;
    return result;
}
std::wstring localFileName(std::string_view remotePath) {
    validateText(remotePath, "remote file path");
    const auto offset = remotePath.find_last_of('/');
    std::wstring name = wide(remotePath.substr(offset == std::string_view::npos ? 0 : offset + 1));
    if (name.empty() || name == L"." || name == L".." || name.back() == L'.' || name.back() == L' ' ||
        std::any_of(name.begin(), name.end(), [](wchar_t c) {
            return c < 32 || std::wstring_view(L"<>:\"/\\|?*").find(c) != std::wstring_view::npos;
        })) throw Error(ErrorCode::InvalidArgument, "Remote filename cannot be used unchanged on Windows");
    auto stem = name.substr(0, name.find(L'.'));
    while (!stem.empty() && stem.back() == L' ') stem.pop_back();
    std::transform(stem.begin(), stem.end(), stem.begin(), [](wchar_t c) { return c >= L'a' && c <= L'z' ? c - 32 : c; });
    const bool deviceNumber = stem.size() == 4 &&
        ((stem[3] >= L'1' && stem[3] <= L'9') || stem[3] == L'\u00b9' || stem[3] == L'\u00b2' || stem[3] == L'\u00b3');
    if (stem == L"CON" || stem == L"PRN" || stem == L"AUX" || stem == L"NUL" ||
        stem == L"CONIN$" || stem == L"CONOUT$" ||
        (deviceNumber && (stem.substr(0, 3) == L"COM" || stem.substr(0, 3) == L"LPT")))
        throw Error(ErrorCode::InvalidArgument, "Remote filename is a reserved Windows device name");
    return name;
}
std::string windowsError(const char* operation, unsigned long code) {
    return std::string(operation) + " (Windows error " + std::to_string(code) + ")";
}
}
