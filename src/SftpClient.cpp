#include "SftpClient.h"
#include <ws2tcpip.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <memory>
#include <optional>

namespace sftp {
namespace {
struct Runtime {
    Runtime() {
        WSADATA data{};
        const int error = WSAStartup(MAKEWORD(2, 2), &data);
        if (error) {
            Error failure(ErrorCode::Network, windowsError("WSAStartup", error));
            failure.systemCode = error; throw failure;
        }
        if (libssh2_init(0)) { WSACleanup(); throw Error(ErrorCode::Ssh, "libssh2 initialization failed"); }
    }
    ~Runtime() { libssh2_exit(); WSACleanup(); }
};
void ensureRuntime() { static Runtime runtime; }

struct CryptoThreadScope {
    // Static OpenSSL on Windows receives no DLL_THREAD_DETACH notification.
    // A 1C worker may never call this instance again: release its thread-local
    // caches at each completed call, without destroying live session contexts.
    ~CryptoThreadScope() { OPENSSL_thread_stop(); }
};

std::string_view readKeyField(std::string_view& blob) {
    if (blob.size() < 4) throw Error(ErrorCode::HostKey, "Invalid server host key encoding");
    const auto* bytes = reinterpret_cast<const unsigned char*>(blob.data());
    const size_t length = (size_t(bytes[0]) << 24) | (size_t(bytes[1]) << 16) |
        (size_t(bytes[2]) << 8) | size_t(bytes[3]);
    blob.remove_prefix(4);
    if (length > blob.size()) throw Error(ErrorCode::HostKey, "Invalid server host key field length");
    const auto field = blob.substr(0, length);
    blob.remove_prefix(length);
    return field;
}
size_t hostKeyBits(std::string_view type, std::string_view fields) {
    if (type == "ssh-ed25519") return 255;
    if (type == "ecdsa-sha2-nistp256") return 256;
    if (type == "ecdsa-sha2-nistp384") return 384;
    if (type == "ecdsa-sha2-nistp521") return 521;
    if (type == "ssh-rsa") readKeyField(fields); // Skip the RSA exponent; measure the modulus.
    else if (type != "ssh-dss") throw Error(ErrorCode::HostKey, "Unsupported server host key type");
    auto number = readKeyField(fields); // RSA modulus or DSA prime p, encoded as SSH mpint.
    while (!number.empty() && number.front() == '\0') number.remove_prefix(1);
    if (number.empty()) throw Error(ErrorCode::HostKey, "Invalid server host key size");
    size_t bits = (number.size() - 1) * 8;
    for (auto leading = static_cast<unsigned char>(number.front()); leading; leading >>= 1) ++bits;
    return bits;
}

struct LocalHandle {
    LocalHandle() = default;
    LocalHandle(const LocalHandle&) = delete;
    LocalHandle& operator=(const LocalHandle&) = delete;
    HANDLE value = INVALID_HANDLE_VALUE;
    ~LocalHandle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
struct TemporaryFile {
    TemporaryFile() = default;
    TemporaryFile(const TemporaryFile&) = delete;
    TemporaryFile& operator=(const TemporaryFile&) = delete;
    std::filesystem::path path;
    ~TemporaryFile() { if (!path.empty()) DeleteFileW(path.c_str()); }
};
[[noreturn]] void failWindows(ErrorCode code, const char* operation, unsigned long status) {
    Error failure(code, windowsError(operation, status));
    failure.systemCode = static_cast<long>(status);
    throw failure;
}
std::string attributesJSON(const std::string& path, const LIBSSH2_SFTP_ATTRIBUTES& attrs,
                           bool exists, bool includeExists) {
    auto end = path.size();
    while (end > 1 && path[end - 1] == '/') --end;
    const auto nameOffset = path.find_last_of('/', end - 1);
    const auto name = path == "/" ? "/" : path.substr(nameOffset == std::string::npos ? 0 : nameOffset + 1,
        end - (nameOffset == std::string::npos ? 0 : nameOffset + 1));
    const bool perms = exists && (attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS);
    const char* type = !perms ? "unknown" : LIBSSH2_SFTP_S_ISDIR(attrs.permissions) ? "directory" :
        LIBSSH2_SFTP_S_ISLNK(attrs.permissions) ? "symlink" : LIBSSH2_SFTP_S_ISREG(attrs.permissions) ? "file" : "unknown";
    std::string result = "{";
    if (includeExists) result += std::string("\"exists\":") + (exists ? "true," : "false,");
    return result + "\"name\":" + jsonString(name) + ",\"path\":" + jsonString(path) +
        ",\"type\":" + jsonString(type) + ",\"size\":" +
        (exists && (attrs.flags & LIBSSH2_SFTP_ATTR_SIZE) ? std::to_string(attrs.filesize) : "null") +
        ",\"modifiedTime\":" + (exists && (attrs.flags & LIBSSH2_SFTP_ATTR_ACMODTIME) ? std::to_string(attrs.mtime) : "null") +
        ",\"permissions\":" + (perms ? std::to_string(attrs.permissions) : "null") + "}";
}
std::string remoteName(std::string_view path) {
    validateText(path, "remote file path");
    const auto offset = path.find_last_of('/');
    std::string name(path.substr(offset == std::string_view::npos ? 0 : offset + 1));
    if (name.empty() || name == "." || name == "..")
        throw Error(ErrorCode::InvalidArgument, "Expected a concrete remote filename");
    return name;
}
}

struct Client::RemoteHandle {
    explicit RemoteHandle(Client& client, LIBSSH2_SFTP_HANDLE* handle = nullptr) : owner(client), value(handle) {}
    RemoteHandle(const RemoteHandle&) = delete;
    RemoteHandle& operator=(const RemoteHandle&) = delete;
    Client& owner;
    LIBSSH2_SFTP_HANDLE* value = nullptr;
    int close() noexcept { return owner.closeRemoteHandle(value); }
    ~RemoteHandle() {
        if (value) close();
        if (owner.transportBroken_) owner.disconnect();
    }
};

int Client::closeRemoteHandle(LIBSSH2_SFTP_HANDLE*& handle) noexcept {
    if (!handle) return 0;
    // In blocking mode libssh2 can return an outer timeout while the handle is
    // still allocated. Nonblocking mode makes EAGAIN unambiguous: retain ownership.
    const int blocking = libssh2_session_get_blocking(session_);
    const auto timeout = libssh2_session_get_timeout(session_);
    libssh2_session_set_blocking(session_, 0);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout);
    int status;
    int waitError = 0;
    while ((status = libssh2_sftp_close_handle(handle)) == LIBSSH2_ERROR_EAGAIN) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (left <= 0) { waitError = LIBSSH2_ERROR_TIMEOUT; break; }
        const int directions = libssh2_session_block_directions(session_);
        fd_set reads, writes;
        FD_ZERO(&reads); FD_ZERO(&writes);
        if (!directions || (directions & LIBSSH2_SESSION_BLOCK_INBOUND)) FD_SET(socket_, &reads);
        if (directions & LIBSSH2_SESSION_BLOCK_OUTBOUND) FD_SET(socket_, &writes);
        timeval wait{static_cast<long>(left / 1000), static_cast<long>((left % 1000) * 1000)};
        const int ready = select(0, &reads, &writes, nullptr, &wait);
        if (ready <= 0) { waitError = ready ? LIBSSH2_ERROR_SOCKET_RECV : LIBSSH2_ERROR_TIMEOUT; break; }
    }
    if (waitError) {
        transportBroken_ = true;
        // A shut-down socket cannot wait for more network data. Finish the
        // interrupted close before freeing its parent SFTP/session structures.
        shutdown(socket_, SD_BOTH);
        do { status = libssh2_sftp_close_handle(handle); } while (status == LIBSSH2_ERROR_EAGAIN);
    }
    handle = nullptr; // Any terminal result frees the handle, including a protocol rejection.
    libssh2_session_set_blocking(session_, blocking);
    if (waitError) {
        libssh2_session_set_last_error(session_, waitError, "Timeout or socket error while closing SFTP handle");
        return waitError;
    }
    return status;
}

Client::~Client() { disconnect(); }
void Client::setTimeout(long seconds) {
    if (seconds < 1 || seconds > 3600) throw Error(ErrorCode::InvalidArgument, "Timeout must be 1..3600 seconds");
    timeoutSeconds_ = seconds;
    if (session_) libssh2_session_set_timeout(session_, seconds * 1000);
}
void Client::disconnect() noexcept {
    const CryptoThreadScope cryptoThread;
    // A failed socket must not keep object destruction waiting for a peer.
    if (socket_ != INVALID_SOCKET) shutdown(socket_, SD_BOTH);
    if (session_) libssh2_session_set_blocking(session_, 0);
    if (sftp_) {
        int status;
        do { status = libssh2_sftp_shutdown(sftp_); } while (status == LIBSSH2_ERROR_EAGAIN);
        sftp_ = nullptr;
    }
    if (session_) {
        libssh2_session_disconnect(session_, "Client disconnected");
        int status;
        do { status = libssh2_session_free(session_); } while (status == LIBSSH2_ERROR_EAGAIN);
        session_ = nullptr;
    }
    if (socket_ != INVALID_SOCKET) { closesocket(socket_); socket_ = INVALID_SOCKET; }
    fingerprint_.clear();
    transportBroken_ = false;
}
void Client::requireConnection() const {
    if (!connected()) throw Error(ErrorCode::NotConnected, "SFTP session is not connected");
}
Error Client::captureError(const char* operation, bool sftpError) const {
    char* details = nullptr;
    int length = 0;
    const int code = session_ ? libssh2_session_last_error(session_, &details, &length, 0) : 0;
    // libssh2 1.11 returns the positive SFTP status for an unadvertised
    // posix-rename extension; this is not a transport failure.
    const bool unsupported = code == static_cast<int>(LIBSSH2_FX_OP_UNSUPPORTED);
    std::string message = std::string(operation) + (unsupported ? " failed (SFTP " : " failed (SSH ") + std::to_string(code);
    const bool protocolError = sftpError && sftp_ && (code == LIBSSH2_ERROR_SFTP_PROTOCOL || unsupported);
    if (protocolError && !unsupported) message += ", SFTP " + std::to_string(libssh2_sftp_last_error(sftp_));
    message += ")";
    if (details && length > 0) message += ": " + std::string(details, length);
    Error failure(protocolError ? ErrorCode::Protocol : ErrorCode::Ssh, message);
    if (!unsupported) failure.sshCode = code;
    if (protocolError) failure.sftpCode = static_cast<long>(unsupported ? LIBSSH2_FX_OP_UNSUPPORTED : libssh2_sftp_last_error(sftp_));
    failure.connectionLost = transportBroken_ || (!protocolError && session_ != nullptr);
    return failure;
}
[[noreturn]] void Client::fail(const char* operation, bool sftpError) {
    auto failure = captureError(operation, sftpError);
    if (failure.connectionLost) disconnect();
    throw failure;
}
void Client::connect(const std::string& host, int port, const std::string& user,
                     const std::string& password, const std::string& expectedFingerprint) {
    const CryptoThreadScope cryptoThread;
    disconnect();
    validateText(host, "host"); validateText(user, "username"); validateText(password, "password", true);
    if (port < 1 || port > 65535) throw Error(ErrorCode::InvalidArgument, "Port must be 1..65535");
    const auto expected = parseHostKeyFingerprint(expectedFingerprint);
    ensureRuntime();
    try {
        ADDRINFOW hints{};
        hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM; hints.ai_protocol = IPPROTO_TCP;
        ADDRINFOW* addresses = nullptr;
        const auto hostW = wide(host);
        const auto service = std::to_wstring(port);
        const int resolveError = GetAddrInfoW(hostW.c_str(), service.c_str(), &hints, &addresses);
        if (resolveError) failWindows(ErrorCode::Network, "Resolve host", resolveError);
        std::unique_ptr<ADDRINFOW, decltype(&FreeAddrInfoW)> addressGuard(addresses, FreeAddrInfoW);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeoutSeconds_);
        int lastError = WSAECONNREFUSED;
        for (auto address = addresses; address; address = address->ai_next) {
            const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
            if (left <= 0) { lastError = WSAETIMEDOUT; break; }
            SOCKET candidate = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
            if (candidate == INVALID_SOCKET) { lastError = WSAGetLastError(); continue; }
            u_long mode = 1;
            if (ioctlsocket(candidate, FIONBIO, &mode)) {
                lastError = WSAGetLastError(); closesocket(candidate); continue;
            }
            int status = ::connect(candidate, address->ai_addr, static_cast<int>(address->ai_addrlen));
            if (status == SOCKET_ERROR) {
                lastError = WSAGetLastError();
                if (lastError == WSAEWOULDBLOCK || lastError == WSAEINPROGRESS) {
                    fd_set writable, errors;
                    FD_ZERO(&writable); FD_ZERO(&errors);
                    FD_SET(candidate, &writable); FD_SET(candidate, &errors);
                    timeval wait{ static_cast<long>(left / 1000), static_cast<long>((left % 1000) * 1000) };
                    status = select(0, nullptr, &writable, &errors, &wait);
                    if (status > 0) {
                        int errorLength = sizeof(lastError);
                        if (getsockopt(candidate, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&lastError), &errorLength))
                            lastError = WSAGetLastError();
                        status = lastError ? SOCKET_ERROR : 0;
                    } else { lastError = status == 0 ? WSAETIMEDOUT : WSAGetLastError(); status = SOCKET_ERROR; }
                }
            }
            if (status != SOCKET_ERROR) { socket_ = candidate; break; }
            closesocket(candidate);
        }
        if (socket_ == INVALID_SOCKET) failWindows(ErrorCode::Network, "Connect", lastError);
        u_long blocking = 0;
        if (ioctlsocket(socket_, FIONBIO, &blocking))
            failWindows(ErrorCode::Network, "Set socket mode", WSAGetLastError());
        session_ = libssh2_session_init();
        if (!session_) throw Error(ErrorCode::Memory, "Cannot allocate SSH session");
        libssh2_session_set_blocking(session_, 1);
        libssh2_session_set_timeout(session_, timeoutSeconds_ * 1000);
        if (!expected.keyType.empty()) {
            // RSA SHA-2 signatures use the same ssh-rsa public key blob.
            const auto methods = expected.keyType == "ssh-rsa"
                ? std::string("rsa-sha2-512,rsa-sha2-256,ssh-rsa") : expected.keyType;
            if (libssh2_session_method_pref(session_, LIBSSH2_METHOD_HOSTKEY, methods.c_str()))
                fail("Select expected server host key algorithm", false);
        }
        if (libssh2_session_handshake(session_, socket_)) fail("SSH handshake", false);
        const char* hash = libssh2_hostkey_hash(session_, LIBSSH2_HOSTKEY_HASH_SHA256);
        if (!hash) throw Error(ErrorCode::HostKey, "Cannot calculate server host key fingerprint");
        std::array<unsigned char, 45> base64{};
        const int encoded = EVP_EncodeBlock(base64.data(), reinterpret_cast<const unsigned char*>(hash), 32);
        if (encoded != 44) throw Error(ErrorCode::HostKey, "Cannot encode server host key fingerprint");
        const std::string actualHash(reinterpret_cast<char*>(base64.data()), 43);
        size_t keyLength = 0;
        int keyType = LIBSSH2_HOSTKEY_TYPE_UNKNOWN;
        const char* key = libssh2_session_hostkey(session_, &keyLength, &keyType);
        if (!key) throw Error(ErrorCode::HostKey, "Cannot read server host key");
        std::string_view fields(key, keyLength);
        const auto actualType = readKeyField(fields);
        fingerprint_ = std::string(actualType) + " " + std::to_string(hostKeyBits(actualType, fields)) + " " + actualHash;
        if (!expected.keyType.empty() && actualType != expected.keyType)
            throw Error(ErrorCode::HostKey, "Server host key type mismatch; received " + std::string(actualType));
        if (!expected.fingerprint.empty() && CRYPTO_memcmp(expected.fingerprint.data(), actualHash.data(), actualHash.size()) != 0)
            throw Error(ErrorCode::HostKey, "Server host key fingerprint mismatch; received " + fingerprint_);
        if (libssh2_userauth_password_ex(session_, user.data(), static_cast<unsigned int>(user.size()),
                password.data(), static_cast<unsigned int>(password.size()), nullptr)) fail("Password authentication", false);
        sftp_ = libssh2_sftp_init(session_);
        if (!sftp_) fail("Initialize SFTP", false);
    } catch (...) { disconnect(); throw; }
}
LIBSSH2_SFTP_HANDLE* Client::openRead(const std::string& path) {
    requireConnection(); remoteName(path);
    auto handle = libssh2_sftp_open_ex(sftp_, path.data(), static_cast<unsigned int>(path.size()),
        LIBSSH2_FXF_READ, 0, LIBSSH2_SFTP_OPENFILE);
    if (!handle) fail("Open remote file");
    return handle;
}
void Client::download(const std::string& path,
                      const std::function<void(std::uint64_t, bool)>& begin,
                      const std::function<void(const char*, std::size_t)>& write) {
    RemoteHandle file{*this, openRead(path)};
    // Close handles before fail() is allowed to invalidate their parent session.
    auto fileFailure = [&](const char* operation) {
        auto failure = captureError(operation);
        file.close();
        failure.connectionLost = failure.connectionLost || transportBroken_;
        if (failure.connectionLost) disconnect();
        throw failure;
    };
    LIBSSH2_SFTP_ATTRIBUTES attrs{};
    if (libssh2_sftp_fstat(file.value, &attrs)) fileFailure("Stat remote file");
    if ((attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) && LIBSSH2_SFTP_S_ISDIR(attrs.permissions))
        throw Error(ErrorCode::InvalidArgument, "Remote path points to a directory");
    const bool knownSize = (attrs.flags & LIBSSH2_SFTP_ATTR_SIZE) != 0;
    begin(attrs.filesize, knownSize);
    std::array<char, 64 * 1024> buffer{};
    std::uint64_t total = 0;
    for (;;) {
        const auto received = libssh2_sftp_read(file.value, buffer.data(), buffer.size());
        if (received < 0) fileFailure("Read remote file");
        if (received == 0) break;
        write(buffer.data(), static_cast<std::size_t>(received));
        total += received;
    }
    if (file.close()) fail("Close remote file");
    if (knownSize && total != attrs.filesize)
        throw Error(ErrorCode::Protocol, "Remote file size changed during download; result discarded");
}
std::vector<char> Client::getFileBinData(const std::string& path) {
    const CryptoThreadScope cryptoThread;
    std::vector<char> data;
    download(path, [&](std::uint64_t size, bool known) {
        if (known) {
            if (size > UINT32_MAX || size > data.max_size())
                throw Error(ErrorCode::Memory, "File exceeds Native API binary data capacity");
            data.reserve(static_cast<std::size_t>(size));
        }
    }, [&](const char* bytes, std::size_t size) {
        if (data.size() > UINT32_MAX - size) throw Error(ErrorCode::Memory, "File exceeds Native API binary data capacity");
        data.insert(data.end(), bytes, bytes + size);
    });
    return data;
}
std::wstring Client::getFile(const std::string& path, const std::wstring& localPath, bool failIfExists) {
    const CryptoThreadScope cryptoThread;
    requireConnection();
    remoteName(path);
    if (localPath.empty() || localPath.find(L'\0') != std::wstring::npos)
        throw Error(ErrorCode::InvalidArgument, "Invalid local file path");
    const std::filesystem::path requested(localPath);
    if (!requested.is_absolute() || requested.filename().empty())
        throw Error(ErrorCode::InvalidArgument, "Local path must be an absolute path including a filename");
    localFileName(utf8(requested.filename().wstring()));
    const auto destination = requested.lexically_normal();
    const auto targetDirectory = destination.parent_path();
    std::filesystem::create_directories(targetDirectory);
    TemporaryFile temporary;
    LocalHandle file;
    static std::atomic<unsigned long long> counter{0};
    for (int attempt = 0; attempt < 100; ++attempt) {
        auto candidate = targetDirectory / (L".sftp-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
            std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(counter++) + L".tmp");
        file.value = CreateFileW(candidate.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file.value != INVALID_HANDLE_VALUE) { temporary.path = std::move(candidate); break; }
        const auto error = GetLastError();
        if (error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS)
            failWindows(ErrorCode::LocalFile, "Create temporary file", error);
    }
    if (file.value == INVALID_HANDLE_VALUE) throw Error(ErrorCode::LocalFile, "Cannot create a unique temporary file");
    download(path, [](std::uint64_t, bool) {}, [&](const char* bytes, std::size_t size) {
        while (size) {
            DWORD written = 0;
            if (!WriteFile(file.value, bytes, static_cast<DWORD>(size), &written, nullptr))
                failWindows(ErrorCode::LocalFile, "Write local file", GetLastError());
            if (!written) throw Error(ErrorCode::LocalFile, "Local write returned zero bytes");
            bytes += written; size -= written;
        }
    });
    if (!FlushFileBuffers(file.value)) failWindows(ErrorCode::LocalFile, "Flush local file", GetLastError());
    const auto finished = file.value; file.value = INVALID_HANDLE_VALUE;
    if (!CloseHandle(finished)) failWindows(ErrorCode::LocalFile, "Close local file", GetLastError());
    // The final filesystem operation enforces no-replace, including concurrent creation.
    const DWORD flags = MOVEFILE_WRITE_THROUGH | (failIfExists ? 0 : MOVEFILE_REPLACE_EXISTING);
    if (!MoveFileExW(temporary.path.c_str(), destination.c_str(), flags))
        failWindows(ErrorCode::LocalFile, "Save local file", GetLastError());
    temporary.path.clear();
    return destination.wstring();
}
std::string Client::listFiles(const std::string& directory) {
    const CryptoThreadScope cryptoThread;
    requireConnection(); validateText(directory, "remote directory");
    RemoteHandle handle{*this, libssh2_sftp_opendir(sftp_, directory.c_str())};
    if (!handle.value) fail("Open remote directory");
    std::vector<std::pair<std::string, std::string>> entries;
    // SFTP names may be longer than MAX_PATH; no fixed Windows path buffer.
    std::vector<char> name(64 * 1024);
    for (;;) {
        LIBSSH2_SFTP_ATTRIBUTES attrs{};
        const int length = libssh2_sftp_readdir_ex(handle.value, name.data(), name.size(), nullptr, 0, &attrs);
        if (length < 0) {
            auto failure = captureError("Read remote directory");
            handle.close();
            failure.connectionLost = failure.connectionLost || transportBroken_;
            if (failure.connectionLost) disconnect();
            throw failure;
        }
        if (!length) break;
        std::string fileName(name.data(), length);
        if (fileName == "." || fileName == "..") continue;
        std::string entry = attributesJSON(joinRemote(directory, fileName), attrs, true, false);
        entries.emplace_back(std::move(fileName), std::move(entry));
    }
    if (handle.close()) fail("Close remote directory");
    std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
    std::string result = "[";
    for (const auto& entry : entries) { if (result.size() > 1) result += ','; result += entry.second; }
    return result + "]";
}
std::string Client::stat(const std::string& path, bool followSymlinks) {
    const CryptoThreadScope cryptoThread;
    requireConnection(); validateText(path, "remote path");
    LIBSSH2_SFTP_ATTRIBUTES attrs{};
    if (libssh2_sftp_stat_ex(sftp_, path.data(), static_cast<unsigned int>(path.size()),
            followSymlinks ? LIBSSH2_SFTP_STAT : LIBSSH2_SFTP_LSTAT, &attrs)) {
        const int sshCode = libssh2_session_last_errno(session_);
        const auto status = libssh2_sftp_last_error(sftp_);
        if (sshCode == LIBSSH2_ERROR_SFTP_PROTOCOL &&
            (status == LIBSSH2_FX_NO_SUCH_FILE || status == LIBSSH2_FX_NO_SUCH_PATH))
            return attributesJSON(path, {}, false, true);
        fail("Stat remote path");
    }
    return attributesJSON(path, attrs, true, true);
}
void Client::moveFile(const std::string& source, const std::string& targetPath, bool overwrite) {
    const CryptoThreadScope cryptoThread;
    requireConnection(); remoteName(source); remoteName(targetPath);
    const auto slash = targetPath.find_last_of('/');
    const auto targetDirectory = slash == std::string::npos ? "." : slash == 0 ? "/" : targetPath.substr(0, slash);
    LIBSSH2_SFTP_ATTRIBUTES directory{};
    if (libssh2_sftp_stat(sftp_, targetDirectory.c_str(), &directory)) fail("Stat target directory");
    if (!(directory.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) || !LIBSSH2_SFTP_S_ISDIR(directory.permissions))
        throw Error(ErrorCode::InvalidArgument, "Target path must be an existing remote directory");
    LIBSSH2_SFTP_ATTRIBUTES attrs{};
    if (libssh2_sftp_lstat(sftp_, source.c_str(), &attrs)) fail("Stat source file");
    if ((attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) && LIBSSH2_SFTP_S_ISDIR(attrs.permissions))
        throw Error(ErrorCode::InvalidArgument, "MoveFile accepts a file, not a directory");
    if (source == targetPath) return;
    // Replacement is delegated to the server extension, never delete-then-rename.
    const int status = overwrite ? libssh2_sftp_posix_rename_ex(sftp_, source.data(), source.size(), targetPath.data(), targetPath.size()) :
        libssh2_sftp_rename_ex(sftp_, source.data(), static_cast<unsigned int>(source.size()),
            targetPath.data(), static_cast<unsigned int>(targetPath.size()), 0);
    if (status) {
        auto failure = captureError(overwrite ? "Replace remote file (posix-rename required)" : "Move remote file");
        failure.outcomeUnknown = failure.connectionLost;
        if (failure.connectionLost) disconnect();
        throw failure;
    }
}
void Client::deleteFile(const std::string& path) {
    const CryptoThreadScope cryptoThread;
    requireConnection(); remoteName(path);
    if (libssh2_sftp_unlink_ex(sftp_, path.data(), static_cast<unsigned int>(path.size()))) {
        auto failure = captureError("Delete remote file");
        failure.outcomeUnknown = failure.connectionLost;
        if (failure.connectionLost) disconnect();
        throw failure;
    }
}
bool Client::putFile(const std::wstring& localPath, const std::string& remotePath,
                     bool deleteSource, bool newerOnly) {
    const CryptoThreadScope cryptoThread;
    UploadReport report;
    report.localPath = utf8(localPath);
    report.remotePath = remotePath;
    report.failedFile = utf8(std::filesystem::path(localPath).filename().wstring());
    LocalHandle source;
    RemoteHandle remote{*this};
    const auto cleanup = [&] {
        // Capture the original failure before cleanup; never invalidate a session with a live handle.
        if (session_) libssh2_session_set_timeout(session_, 1000);
        if (remote.value) remote.close();
        if (sftp_ && !transportBroken_ && !report.temporaryPath.empty() &&
            !libssh2_sftp_unlink_ex(sftp_, report.temporaryPath.data(), static_cast<unsigned int>(report.temporaryPath.size())))
            report.temporaryPath.clear();
        if (session_) libssh2_session_set_timeout(session_, timeoutSeconds_ * 1000);
    };
    try {
        requireConnection(); remoteName(remotePath);
        if (localPath.empty() || localPath.find(L'\0') != std::wstring::npos ||
            !std::filesystem::path(localPath).is_absolute() || std::filesystem::path(localPath).filename().empty())
            throw Error(ErrorCode::InvalidArgument, "Local source must be an absolute path including a filename");
        source.value = CreateFileW(localPath.c_str(), GENERIC_READ | (deleteSource ? DELETE : 0), FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (source.value == INVALID_HANDLE_VALUE) failWindows(ErrorCode::LocalFile, "Open local upload source", GetLastError());
        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(source.value, &info)) failWindows(ErrorCode::LocalFile, "Stat local upload source", GetLastError());
        if (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))
            throw Error(ErrorCode::InvalidArgument, "Upload source must be a regular file, not a directory or link");
        ULARGE_INTEGER modified{};
        modified.LowPart = info.ftLastWriteTime.dwLowDateTime; modified.HighPart = info.ftLastWriteTime.dwHighDateTime;
        constexpr unsigned long long unixEpoch = 116444736000000000ULL;
        if (modified.QuadPart < unixEpoch || (modified.QuadPart - unixEpoch) / 10000000ULL > UINT32_MAX)
            throw Error(ErrorCode::InvalidArgument, "Source timestamp is outside the SFTP v3 range (1970-2106)");
        const auto mtime = static_cast<unsigned long>((modified.QuadPart - unixEpoch) / 10000000ULL);
        const auto expectedSize = (std::uint64_t(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
        const auto slash = remotePath.find_last_of('/');
        const auto directory = slash == std::string::npos ? "." : slash == 0 ? "/" : remotePath.substr(0, slash);
        LIBSSH2_SFTP_ATTRIBUTES attrs{};
        if (libssh2_sftp_stat(sftp_, directory.c_str(), &attrs)) throw captureError("Stat upload target directory");
        if (!(attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) || !LIBSSH2_SFTP_S_ISDIR(attrs.permissions))
            throw Error(ErrorCode::InvalidArgument, "Upload target directory must already exist");
        attrs = {};
        bool exists = true;
        if (libssh2_sftp_lstat(sftp_, remotePath.c_str(), &attrs)) {
            auto failure = captureError("Stat upload target");
            if (failure.sftpCode && (*failure.sftpCode == LIBSSH2_FX_NO_SUCH_FILE || *failure.sftpCode == LIBSSH2_FX_NO_SUCH_PATH))
                exists = false;
            else throw failure;
        }
        if (exists && (!(attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) || !LIBSSH2_SFTP_S_ISREG(attrs.permissions)))
            throw Error(ErrorCode::InvalidArgument, "Upload target must be a regular file, not a directory or link");
        if (newerOnly && exists) {
            if (!(attrs.flags & LIBSSH2_SFTP_ATTR_ACMODTIME))
                throw Error(ErrorCode::Protocol, "Server did not return target modification time for NewerOnly");
            if (mtime <= attrs.mtime) return false;
        }
        // Random, exclusively created temporary name in the destination directory.
        for (int attempt = 0; attempt < 10; ++attempt) {
            std::array<unsigned char, 16> random{};
            if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1)
                throw Error(ErrorCode::Internal, "Cannot generate upload temporary filename");
            std::string name = ".sftp-";
            constexpr char hex[] = "0123456789abcdef";
            for (const auto byte : random) { name += hex[byte >> 4]; name += hex[byte & 15]; }
            auto candidate = joinRemote(directory, name + ".tmp");
            remote.value = libssh2_sftp_open_ex(sftp_, candidate.data(), static_cast<unsigned int>(candidate.size()),
                LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_EXCL, 0644, LIBSSH2_SFTP_OPENFILE);
            if (remote.value) { report.temporaryPath = std::move(candidate); break; }
            auto failure = captureError("Create remote upload temporary file");
            if (!failure.sftpCode || *failure.sftpCode != LIBSSH2_FX_FILE_ALREADY_EXISTS) throw failure;
        }
        if (!remote.value) throw Error(ErrorCode::Protocol, "Cannot create a unique remote upload temporary file");
        std::array<char, 64 * 1024> buffer{};
        std::uint64_t total = 0;
        for (;;) {
            DWORD received = 0;
            if (!ReadFile(source.value, buffer.data(), static_cast<DWORD>(buffer.size()), &received, nullptr))
                failWindows(ErrorCode::LocalFile, "Read local upload source", GetLastError());
            if (!received) break;
            std::size_t offset = 0;
            while (offset < received) {
                const auto written = libssh2_sftp_write(remote.value, buffer.data() + offset, received - offset);
                if (written < 0) throw captureError("Write remote upload file");
                if (!written) throw Error(ErrorCode::Protocol, "Remote upload write returned zero bytes");
                offset += static_cast<std::size_t>(written);
            }
            total += received;
        }
        if (total != expectedSize) throw Error(ErrorCode::LocalFile, "Local upload source size changed during transfer");
        attrs = {};
        if (libssh2_sftp_fstat(remote.value, &attrs)) throw captureError("Stat remote uploaded file");
        if (!(attrs.flags & LIBSSH2_SFTP_ATTR_SIZE) || attrs.filesize != total)
            throw Error(ErrorCode::Protocol, "Remote uploaded size does not match source");
        attrs = {}; attrs.flags = LIBSSH2_SFTP_ATTR_ACMODTIME; attrs.atime = mtime; attrs.mtime = mtime;
        if (libssh2_sftp_fstat_ex(remote.value, &attrs, 1)) throw captureError("Set uploaded file timestamp");
        if (remote.close()) throw captureError("Close remote uploaded file");
        // Never delete the previous destination to emulate replacement.
        const int status = exists ? libssh2_sftp_posix_rename_ex(sftp_, report.temporaryPath.data(), report.temporaryPath.size(),
            remotePath.data(), remotePath.size()) : libssh2_sftp_rename_ex(sftp_, report.temporaryPath.data(),
            static_cast<unsigned int>(report.temporaryPath.size()), remotePath.data(), static_cast<unsigned int>(remotePath.size()), 0);
        if (status) {
            auto failure = captureError("Publish uploaded file (replacement requires posix-rename)");
            failure.outcomeUnknown = failure.connectionLost;
            throw failure;
        }
        report.temporaryPath.clear();
        report.transferCompleted = true;
        if (deleteSource) {
            // Delete the exact source handle, never an unrelated file substituted at the path.
            FILE_DISPOSITION_INFO disposition{}; disposition.DeleteFile = TRUE;
            if (!SetFileInformationByHandle(source.value, FileDispositionInfo, &disposition, sizeof(disposition)))
                failWindows(ErrorCode::LocalFile, "Upload completed, but deleting local source failed", GetLastError());
            report.sourceDeleted = true;
        }
        return true;
    } catch (Error& failure) {
        cleanup();
        failure.connectionLost = failure.connectionLost || transportBroken_;
        if (failure.connectionLost) disconnect();
        if (report.transferCompleted) report.uploaded.push_back(report.failedFile);
        failure.upload = std::move(report);
        throw;
    } catch (...) {
        cleanup();
        throw;
    }
}
std::string Client::putFiles(const std::wstring& localDirectory, const std::string& remoteDirectory,
                             bool deleteSource, bool newerOnly) {
    const CryptoThreadScope cryptoThread;
    requireConnection(); validateText(remoteDirectory, "remote upload directory");
    if (localDirectory.empty() || localDirectory.find(L'\0') != std::wstring::npos ||
        !std::filesystem::path(localDirectory).is_absolute())
        throw Error(ErrorCode::InvalidArgument, "Local upload directory must be an absolute path");
    UploadReport report;
    report.localPath = utf8(localDirectory); report.remotePath = remoteDirectory;
    try {
        std::vector<std::filesystem::path> files;
        for (const auto& entry : std::filesystem::directory_iterator(localDirectory)) {
            const auto attributes = GetFileAttributesW(entry.path().c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES) failWindows(ErrorCode::LocalFile, "Inspect upload directory entry", GetLastError());
            if (!(attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) files.push_back(entry.path());
        }
        std::sort(files.begin(), files.end());
        for (const auto& file : files) report.pending.push_back(utf8(file.filename().wstring()));
        // Validate even for an empty local directory.
        LIBSSH2_SFTP_ATTRIBUTES attrs{};
        if (libssh2_sftp_stat(sftp_, remoteDirectory.c_str(), &attrs)) fail("Stat batch upload target directory");
        if (!(attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) || !LIBSSH2_SFTP_S_ISDIR(attrs.permissions))
            throw Error(ErrorCode::InvalidArgument, "Upload target directory must already exist");
        std::size_t processed = 0;
        for (const auto& file : files) {
            const auto name = utf8(file.filename().wstring());
            ++processed;
            try {
                if (putFile(file.wstring(), joinRemote(remoteDirectory, name), deleteSource, newerOnly)) report.uploaded.push_back(name);
                else report.skipped.push_back(name);
            } catch (Error& failure) {
                report.pending.erase(report.pending.begin(), report.pending.begin() + processed);
                if (failure.upload) {
                    auto progress = std::move(*failure.upload);
                    report.failedFile = name; report.localPath = std::move(progress.localPath); report.remotePath = std::move(progress.remotePath);
                    report.temporaryPath = std::move(progress.temporaryPath);
                    report.transferCompleted = progress.transferCompleted; report.sourceDeleted = progress.sourceDeleted;
                    if (progress.transferCompleted) report.uploaded.push_back(name);
                } else report.failedFile = name;
                throw;
            }
        }
        report.pending.clear();
        return report.json(false);
    } catch (Error& failure) { failure.upload = std::move(report); throw; }
    catch (const std::filesystem::filesystem_error& error) {
        Error failure(ErrorCode::LocalFile, error.what()); failure.systemCode = error.code().value();
        failure.upload = std::move(report); throw failure;
    }
}
}
