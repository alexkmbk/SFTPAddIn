#pragma once
#include "Utils.h"
#include <winsock2.h>
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <cstdint>
#include <functional>
#include <vector>

namespace sftp {
class Client {
public:
    Client() = default;
    ~Client();
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;
    void connect(const std::string& host, int port, const std::string& user,
                 const std::string& password, const std::string& fingerprint);
    void disconnect() noexcept;
    bool connected() const noexcept { return sftp_ != nullptr; }
    const std::string& fingerprint() const noexcept { return fingerprint_; }
    void setTimeout(long seconds);
    long timeout() const noexcept { return timeoutSeconds_; }
    std::string listFiles(const std::string& directory);
    std::vector<char> getFileBinData(const std::string& path);
    std::wstring getFile(const std::string& path, const std::wstring& localPath, bool failIfExists = false);
    void moveFile(const std::string& source, const std::string& targetPath, bool overwrite = false);
    std::string stat(const std::string& path, bool followSymlinks = false);
    void deleteFile(const std::string& path);
    bool putFile(const std::wstring& localPath, const std::string& remotePath,
                 bool deleteSource = false, bool newerOnly = false);
    std::string putFiles(const std::wstring& localDirectory, const std::string& remoteDirectory,
                         bool deleteSource = false, bool newerOnly = false);
private:
    struct RemoteHandle;
    int closeRemoteHandle(LIBSSH2_SFTP_HANDLE*& handle) noexcept;
    void requireConnection() const;
    [[noreturn]] void fail(const char* operation, bool sftpError = true);
    Error captureError(const char* operation, bool sftpError = true) const;
    LIBSSH2_SFTP_HANDLE* openRead(const std::string& path);
    void download(const std::string& path,
                  const std::function<void(std::uint64_t, bool)>& begin,
                  const std::function<void(const char*, std::size_t)>& write);
    SOCKET socket_ = INVALID_SOCKET;
    LIBSSH2_SESSION* session_ = nullptr;
    LIBSSH2_SFTP* sftp_ = nullptr;
    std::string fingerprint_;
    long timeoutSeconds_ = 30;
    bool transportBroken_ = false;
};
}
