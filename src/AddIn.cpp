#include "AddIn.h"
#include <array>
#include <cmath>
#include <cstring>
#include <limits>

namespace {
struct Name { const wchar_t* english; const wchar_t* russian; };
constexpr std::array<Name, 10> methods{{
    {L"Connect", L"Подключить"}, {L"Disconnect", L"Отключить"},
    {L"ListFiles", L"СписокФайлов"}, {L"GetFile", L"ПолучитьФайл"},
    {L"GetFileBinData", L"ПолучитьФайлДвоичныеДанные"},
    {L"MoveFile", L"ПереместитьФайл"}, {L"DeleteFile", L"УдалитьФайл"},
    {L"Stat", L"СведенияОФайле"},
    {L"PutFile", L"ОтправитьФайл"}, {L"PutFiles", L"ОтправитьФайлы"}
}};
constexpr std::array<Name, 6> properties{{
    {L"Connected", L"Подключен"}, {L"Timeout", L"Таймаут"},
    {L"HostKeyFingerprint", L"ОтпечатокКлючаСервера"},
    {L"LastError", L"ПоследняяОшибка"},
    {L"Version", L"Версия"}, {L"LastErrorDetails", L"ПодробностиПоследнейОшибки"}
}};
constexpr std::array<long, 10> parameterCounts{5, 0, 1, 3, 1, 3, 1, 2, 4, 4};
constexpr std::array<long, 10> requiredCounts{4, 0, 1, 2, 1, 2, 1, 1, 2, 2};
template<std::size_t N> long findName(const std::array<Name, N>& names, const wchar_t* name) {
    if (!name) return -1;
    for (std::size_t i = 0; i < N; ++i)
        if (CompareStringOrdinal(name, -1, names[i].english, -1, TRUE) == CSTR_EQUAL ||
            CompareStringOrdinal(name, -1, names[i].russian, -1, TRUE) == CSTR_EQUAL)
            return static_cast<long>(i);
    return -1;
}
std::wstring argumentString(const tVariant& value) {
    if (value.vt != VTYPE_PWSTR || (!value.pwstrVal && value.wstrLen))
        throw sftp::Error(sftp::ErrorCode::InvalidArgument, "Expected a string parameter");
    return value.wstrLen ? std::wstring(value.pwstrVal, value.wstrLen) : std::wstring{};
}
long integer(const tVariant& value, long minimum, long maximum) {
    double number = 0;
    switch (value.vt) {
    case VTYPE_I1: number = value.i8Val; break;
    case VTYPE_I2: number = value.shortVal; break;
    case VTYPE_I4: number = value.lVal; break;
    case VTYPE_INT: number = value.intVal; break;
    case VTYPE_UI1: number = value.ui8Val; break;
    case VTYPE_UI2: number = value.ushortVal; break;
    case VTYPE_UI4: number = value.ulVal; break;
    case VTYPE_UINT: number = value.uintVal; break;
    case VTYPE_I8: number = static_cast<double>(value.llVal); break;
    case VTYPE_UI8: number = static_cast<double>(value.ullVal); break;
    case VTYPE_R4: number = value.fltVal; break;
    case VTYPE_R8: number = value.dblVal; break;
    default: throw sftp::Error(sftp::ErrorCode::InvalidArgument, "Expected a numeric parameter");
    }
    if (!std::isfinite(number) || number < minimum || number > maximum || std::trunc(number) != number)
        throw sftp::Error(sftp::ErrorCode::InvalidArgument, "Numeric parameter is out of range or is not an integer");
    return static_cast<long>(number);
}
struct Password {
    std::string value;
    ~Password() { if (!value.empty()) SecureZeroMemory(value.data(), value.size()); }
};
bool booleanArgument(const tVariant& value) {
    if (value.vt != VTYPE_BOOL)
        throw sftp::Error(sftp::ErrorCode::InvalidArgument, "Expected a boolean parameter");
    return value.bVal;
}
}

bool SftpAddIn::Init(void* connection) {
    try {
        const std::lock_guard<std::recursive_mutex> lock(mutex_);
        connection_ = static_cast<IAddInDefBase*>(connection);
        return connection_ != nullptr;
    } catch (...) { return false; }
}
bool SftpAddIn::setMemManager(void* memory) {
    try {
        const std::lock_guard<std::recursive_mutex> lock(mutex_);
        memory_ = static_cast<IMemoryManager*>(memory);
        return memory_ != nullptr;
    } catch (...) { return false; }
}
long SftpAddIn::GetInfo() { return 2100; }
void SftpAddIn::Done() {
    try {
        const std::lock_guard<std::recursive_mutex> lock(mutex_);
        client_.disconnect();
        connection_ = nullptr;
    } catch (...) {}
}
WCHAR_T* SftpAddIn::allocateString(std::wstring_view text) {
    const std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!memory_) throw sftp::Error(sftp::ErrorCode::Memory, "1C memory manager is not initialized");
    if (text.size() > (ULONG_MAX / sizeof(wchar_t)) - 1) throw std::bad_alloc();
    wchar_t* result = nullptr;
    const auto bytes = static_cast<unsigned long>((text.size() + 1) * sizeof(wchar_t));
    if (!memory_->AllocMemory(reinterpret_cast<void**>(&result), bytes) || !result) throw std::bad_alloc();
    if (!text.empty()) std::memcpy(result, text.data(), text.size() * sizeof(wchar_t));
    result[text.size()] = 0;
    return result;
}
void SftpAddIn::stringResult(tVariant* value, std::wstring_view text) {
    auto buffer = allocateString(text);
    value->pwstrVal = buffer; value->wstrLen = static_cast<std::uint32_t>(text.size()); value->vt = VTYPE_PWSTR;
}
void SftpAddIn::clearError() {
    std::wstring{}.swap(lastError_);
    lastErrorCode_ = 0;
    std::wstring(L"{}").swap(lastErrorDetails_);
}
void SftpAddIn::beginCall(long method, tVariant* parameters, long count) {
    context_ = {};
    context_.operation = method >= 0 && method < GetNMethods() ? sftp::utf8(methods[method].english) : "Unknown";
    // Context contains only file paths. Connect credentials are never captured.
    const auto path = [&](long index) {
        return parameters && index < count && parameters[index].vt == VTYPE_PWSTR ?
            sftp::utf8(argumentString(parameters[index])) : std::string{};
    };
    if (method >= 2 && method <= 7) context_.remotePath = path(0);
    if (method == 3) context_.localPath = path(1);
    if (method == 5) context_.targetPath = path(1);
    if (method == 8 || method == 9) { context_.localPath = path(0); context_.remotePath = path(1); }
}
void SftpAddIn::error(sftp::ErrorCode code, const char* message, const sftp::Error* details) noexcept {
    try {
        const std::lock_guard<std::recursive_mutex> lock(mutex_);
        lastErrorCode_ = static_cast<long>(code);
        try {
            try { lastError_ = sftp::wide(message); } catch (...) { lastError_ = L"SFTP operation failed"; }
            const auto number = [](const std::optional<long>& value) { return value ? std::to_string(*value) : "null"; };
            const auto empty = std::optional<long>{};
            lastErrorDetails_ = sftp::wide("{\"code\":" + std::to_string(lastErrorCode_) +
                ",\"message\":" + sftp::jsonString(sftp::utf8(lastError_)) +
                ",\"operation\":" + sftp::jsonString(context_.operation) +
                ",\"remotePath\":" + sftp::jsonString(details && details->upload ? details->upload->remotePath : context_.remotePath) +
                ",\"targetPath\":" + sftp::jsonString(context_.targetPath) +
                ",\"localPath\":" + sftp::jsonString(details && details->upload ? details->upload->localPath : context_.localPath) +
                ",\"sshCode\":" + number(details ? details->sshCode : empty) +
                ",\"sftpCode\":" + number(details ? details->sftpCode : empty) +
                ",\"systemCode\":" + number(details ? details->systemCode : empty) +
                ",\"connectionLost\":" + (details && details->connectionLost ? "true" : "false") +
                ",\"outcomeUnknown\":" + (details && details->outcomeUnknown ? "true" : "false") +
                (details && details->upload ? ",\"upload\":" + details->upload->json() : "") + "}");
            if (connection_) connection_->AddError(ADDIN_E_FAIL, L"SFTPAddIn", lastError_.c_str(), lastErrorCode_);
        } catch (...) {
            // A partial diagnostic must not accidentally expose the preceding error.
            lastErrorDetails_.clear();
            try { if (connection_) connection_->AddError(ADDIN_E_FAIL, L"SFTPAddIn", L"SFTP operation failed", lastErrorCode_); } catch (...) {}
        }
    } catch (...) {} // A synchronization failure must not cross the Native API boundary.
}
bool SftpAddIn::RegisterExtensionAs(WCHAR_T** name) {
    if (!name) return false;
    *name = nullptr;
    try { *name = allocateString(L"SFTP"); return true; }
    catch (...) { error(sftp::ErrorCode::Memory, "Cannot allocate extension name"); return false; }
}
long SftpAddIn::GetNProps() { return static_cast<long>(properties.size()); }
long SftpAddIn::FindProp(const WCHAR_T* name) { return findName(properties, name); }
const WCHAR_T* SftpAddIn::GetPropName(long number, long alias) {
    if (number < 0 || number >= GetNProps() || alias < 0 || alias > 1) return nullptr;
    try { return allocateString(alias ? properties[number].russian : properties[number].english); }
    catch (...) { error(sftp::ErrorCode::Memory, "Cannot allocate property name"); return nullptr; }
}
bool SftpAddIn::GetPropVal(long number, tVariant* value) {
    if (!value) return false;
    tVarInit(value);
    try {
        const std::lock_guard<std::recursive_mutex> lock(mutex_);
        try {
            switch (number) {
            case 0: value->vt = VTYPE_BOOL; value->bVal = client_.connected(); break;
            case 1: value->vt = VTYPE_I4; value->lVal = client_.timeout(); break;
            case 2: stringResult(value, sftp::wide(client_.fingerprint())); break;
            case 3: stringResult(value, lastError_); break;
            case 4: stringResult(value, L"0.2.0"); break;
            case 5: stringResult(value, lastErrorDetails_); break;
            default: return false;
            }
            return true;
        } catch (...) {
            // Reading diagnostics must never overwrite the operation being diagnosed.
            if (!lastErrorCode_) error(sftp::ErrorCode::Memory, "Cannot return property value");
        }
    } catch (...) {}
    return false;
}
bool SftpAddIn::SetPropVal(long number, tVariant* value) {
    if (number != 1 || !value) return false;
    try {
        const std::lock_guard<std::recursive_mutex> lock(mutex_);
        try {
            clearError();
            context_ = {}; context_.operation = "SetTimeout";
            client_.setTimeout(integer(*value, 1, 3600));
            return true;
        } catch (const sftp::Error& e) { error(e.code, e.what(), &e); }
        catch (...) { error(sftp::ErrorCode::Internal, "Cannot set property"); }
    } catch (...) { error(sftp::ErrorCode::Internal, "Native API property dispatch failed"); }
    return false;
}
bool SftpAddIn::IsPropReadable(long number) { return number >= 0 && number < GetNProps(); }
bool SftpAddIn::IsPropWritable(long number) { return number == 1; }
long SftpAddIn::GetNMethods() { return static_cast<long>(methods.size()); }
long SftpAddIn::FindMethod(const WCHAR_T* name) { return findName(methods, name); }
const WCHAR_T* SftpAddIn::GetMethodName(long number, long alias) {
    if (number < 0 || number >= GetNMethods() || alias < 0 || alias > 1) return nullptr;
    try { return allocateString(alias ? methods[number].russian : methods[number].english); }
    catch (...) { error(sftp::ErrorCode::Memory, "Cannot allocate method name"); return nullptr; }
}
long SftpAddIn::GetNParams(long number) { return number >= 0 && number < GetNMethods() ? parameterCounts[number] : 0; }
bool SftpAddIn::GetParamDefValue(long method, long parameter, tVariant* value) {
    if (!value) return false;
    tVarInit(value);
    try {
        if (method == 0 && parameter == 4) { stringResult(value, L""); return true; }
        if (((method == 3 || method == 5) && parameter == 2) || (method == 7 && parameter == 1) ||
            ((method == 8 || method == 9) && (parameter == 2 || parameter == 3))) {
            value->vt = VTYPE_BOOL; value->bVal = false; return true;
        }
        return false;
    }
    catch (...) { error(sftp::ErrorCode::Memory, "Cannot allocate default parameter"); return false; }
}
bool SftpAddIn::HasRetVal(long number) { return number >= 0 && number < GetNMethods(); }
bool SftpAddIn::CallAsProc(long method, tVariant* parameters, long count) {
    try {
        const std::lock_guard<std::recursive_mutex> lock(mutex_);
        tVariant result{};
        const bool success = CallAsFunc(method, &result, parameters, count);
        if (memory_ && (result.vt == VTYPE_PWSTR || result.vt == VTYPE_BLOB)) {
            void* buffer = result.vt == VTYPE_PWSTR ? static_cast<void*>(result.pwstrVal) : static_cast<void*>(result.pstrVal);
            memory_->FreeMemory(&buffer);
        }
        return success;
    } catch (...) { error(sftp::ErrorCode::Internal, "Native API procedure dispatch failed"); }
    return false;
}
bool SftpAddIn::CallAsFunc(long method, tVariant* result, tVariant* parameters, long count) {
    if (!result) return false;
    tVarInit(result);
    try {
        const std::lock_guard<std::recursive_mutex> lock(mutex_);
        try {
            clearError();
            beginCall(method, parameters, count);
            return dispatch(method, result, parameters, count);
        } catch (const sftp::Error& e) { error(e.code, e.what(), &e); }
        catch (const std::filesystem::filesystem_error& e) {
            sftp::Error failure(sftp::ErrorCode::LocalFile, e.what());
            failure.systemCode = e.code().value(); error(failure.code, failure.what(), &failure);
        }
        catch (const std::bad_alloc&) { error(sftp::ErrorCode::Memory, "Insufficient memory for operation"); }
        catch (const std::exception& e) { error(sftp::ErrorCode::Internal, e.what()); }
        catch (...) { error(sftp::ErrorCode::Internal, "Unexpected SFTP error"); }
    } catch (...) { error(sftp::ErrorCode::Internal, "Native API dispatch failed"); }
    return false;
}
bool SftpAddIn::dispatch(long method, tVariant* result, tVariant* parameters, long count) {
    if (method < 0 || method >= GetNMethods()) throw sftp::Error(sftp::ErrorCode::InvalidArgument, "Unknown method");
    const long required = requiredCounts[method];
    if (count < required || count > parameterCounts[method] || (count && !parameters))
        throw sftp::Error(sftp::ErrorCode::InvalidArgument, "Incorrect number of parameters");
    if (!memory_) throw sftp::Error(sftp::ErrorCode::Memory, "1C memory manager is not initialized");
    const auto text = [&](long index) { return sftp::utf8(argumentString(parameters[index])); };
    const auto flag = [&](long index) { return count > index && parameters[index].vt != VTYPE_EMPTY ? booleanArgument(parameters[index]) : false; };
    switch (method) {
    case 0: {
        const auto host = text(0); const auto port = integer(parameters[1], 1, 65535); const auto user = text(2);
        Password password{text(3)};
        const auto fingerprint = count == 5 && parameters[4].vt != VTYPE_EMPTY ? text(4) : std::string{};
        client_.connect(host, port, user, password.value, fingerprint);
        break;
    }
    case 1: client_.disconnect(); break;
    case 2: stringResult(result, sftp::wide(client_.listFiles(text(0)))); return true;
    case 3: stringResult(result, client_.getFile(text(0), argumentString(parameters[1]), flag(2))); return true;
    case 4: {
        const auto data = client_.getFileBinData(text(0));
        char* buffer = nullptr;
        const auto bytes = static_cast<unsigned long>(data.empty() ? 1 : data.size());
        if (!memory_->AllocMemory(reinterpret_cast<void**>(&buffer), bytes) || !buffer) throw std::bad_alloc();
        if (!data.empty()) std::memcpy(buffer, data.data(), data.size());
        result->pstrVal = buffer; result->strLen = static_cast<std::uint32_t>(data.size()); result->vt = VTYPE_BLOB;
        return true;
    }
    case 5: client_.moveFile(text(0), text(1), flag(2)); break;
    case 6: client_.deleteFile(text(0)); break;
    case 7: stringResult(result, sftp::wide(client_.stat(text(0), flag(1)))); return true;
    case 8: {
        const bool uploaded = client_.putFile(argumentString(parameters[0]), text(1), flag(2), flag(3));
        result->vt = VTYPE_BOOL;
        result->bVal = uploaded;
        return true;
    }
    case 9: stringResult(result, sftp::wide(client_.putFiles(argumentString(parameters[0]), text(1), flag(2), flag(3)))); return true;
    }
    result->vt = VTYPE_BOOL; result->bVal = true;
    return true;
}
