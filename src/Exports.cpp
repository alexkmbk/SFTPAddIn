#include "AddIn.h"
#include <cwchar>

extern "C" long GetClassObject(const WCHAR_T* name, IComponentBase** object) {
    if (!name || !object || *object || std::wcscmp(name, L"SFTP") != 0) return 0;
    try { *object = new SftpAddIn; return 1; }
    catch (...) { return 0; }
}
extern "C" long DestroyObject(IComponentBase** object) {
    if (!object || !*object) return -1;
    try { delete *object; *object = nullptr; return 0; }
    catch (...) { return -1; }
}
extern "C" const WCHAR_T* GetClassNames() { return L"SFTP"; }
extern "C" AppCapabilities SetPlatformCapabilities(AppCapabilities) { return eAppCapabilities1; }
