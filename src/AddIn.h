#pragma once
#include "SftpClient.h"
#include "ComponentBase.h"
#include "AddInDefBase.h"
#include "IMemoryManager.h"
#include <mutex>

class SftpAddIn final : public IComponentBase {
public:
    bool ADDIN_API Init(void* connection) override;
    bool ADDIN_API setMemManager(void* memory) override;
    long ADDIN_API GetInfo() override;
    void ADDIN_API Done() override;
    bool ADDIN_API RegisterExtensionAs(WCHAR_T** name) override;
    long ADDIN_API GetNProps() override;
    long ADDIN_API FindProp(const WCHAR_T* name) override;
    const WCHAR_T* ADDIN_API GetPropName(long number, long alias) override;
    bool ADDIN_API GetPropVal(long number, tVariant* value) override;
    bool ADDIN_API SetPropVal(long number, tVariant* value) override;
    bool ADDIN_API IsPropReadable(long number) override;
    bool ADDIN_API IsPropWritable(long number) override;
    long ADDIN_API GetNMethods() override;
    long ADDIN_API FindMethod(const WCHAR_T* name) override;
    const WCHAR_T* ADDIN_API GetMethodName(long number, long alias) override;
    long ADDIN_API GetNParams(long number) override;
    bool ADDIN_API GetParamDefValue(long method, long parameter, tVariant* value) override;
    bool ADDIN_API HasRetVal(long number) override;
    bool ADDIN_API CallAsProc(long method, tVariant* parameters, long count) override;
    bool ADDIN_API CallAsFunc(long method, tVariant* result, tVariant* parameters, long count) override;
    void ADDIN_API SetLocale(const WCHAR_T*) override {}
private:
    WCHAR_T* allocateString(std::wstring_view text);
    void stringResult(tVariant* value, std::wstring_view text);
    void error(sftp::ErrorCode code, const char* message, const sftp::Error* details = nullptr) noexcept;
    void clearError();
    void beginCall(long method, tVariant* parameters, long count);
    bool dispatch(long method, tVariant* result, tVariant* parameters, long count);
    IAddInDefBase* connection_ = nullptr;
    IMemoryManager* memory_ = nullptr;
    sftp::Client client_;
    std::wstring lastError_;
    long lastErrorCode_ = 0;
    std::wstring lastErrorDetails_ = L"{}";
    struct Context {
        std::string operation, remotePath, targetPath, localPath;
    } context_;
    // Serializes client lifetime, diagnostics and platform interface pointers.
    std::recursive_mutex mutex_;
};
