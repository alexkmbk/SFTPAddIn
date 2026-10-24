#pragma once
#include <filesystem>
#include <stdexcept>
#include <string>
#include <string_view>
#include <optional>
#include <vector>

namespace sftp {
enum class ErrorCode : long {
    InvalidArgument = 1, NotConnected, Network, Ssh, Protocol,
    LocalFile, HostKey, Memory, Internal
};
struct UploadReport {
    std::vector<std::string> uploaded, skipped, pending;
    std::string failedFile, localPath, remotePath, temporaryPath;
    bool transferCompleted = false;
    bool sourceDeleted = false;
    std::string json(bool details = true) const;
};
class Error : public std::runtime_error {
public:
    Error(ErrorCode code, const std::string& message) : std::runtime_error(message), code(code) {}
    ErrorCode code;
    std::optional<long> sshCode;
    std::optional<long> sftpCode;
    std::optional<long> systemCode;
    bool connectionLost = false;
    bool outcomeUnknown = false;
    std::optional<UploadReport> upload;
};
std::string utf8(std::wstring_view value);
std::wstring wide(std::string_view value);
std::string jsonString(std::string_view value);
struct ExpectedHostKey {
    std::string fingerprint;
    std::string keyType;
};
ExpectedHostKey parseHostKeyFingerprint(std::string_view value);
std::wstring localFileName(std::string_view remotePath);
void validateText(std::string_view text, const char* label, bool allowEmpty = false);
std::string joinRemote(std::string_view directory, std::string_view name);
std::string windowsError(const char* operation, unsigned long code);
}
