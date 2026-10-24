// Included after apiTests so this exercises the same Native API host and allocator.
void nativeMemoryTests(Host& host) {
    auto object = host.object;
    const auto noAllocations = [&] {
        check(host.memory.allocations.empty(), "Native API retained a platform allocation between calls");
    };
    const auto releaseName = [&](const WCHAR_T* name) {
        check(name != nullptr, "Native API name allocation failed");
        void* buffer = const_cast<WCHAR_T*>(name);
        host.memory.FreeMemory(&buffer);
    };
    const auto allocationFailure = [&](auto&& operation) {
        noAllocations();
        host.memory.failNext = true;
        operation();
        check(!host.memory.failNext, "Allocation failure was not exercised");
        noAllocations();
    };
    const auto timeoutProperty = object->FindProp(L"Timeout");
    const auto connectMethod = object->FindMethod(L"Connect");
    host.invoke(L"Disconnect");
    noAllocations();
    for (long iteration = 0; iteration < 1000; ++iteration) {
        for (const auto property : {L"Connected", L"Timeout", L"HostKeyFingerprint", L"LastError", L"Version", L"LastErrorDetails"}) {
            { auto result = host.property(property); }
            noAllocations();
        }
        const auto methodIndex = iteration % object->GetNMethods();
        const auto propertyIndex = iteration % object->GetNProps();
        for (long alias = 0; alias != 2; ++alias) {
            const auto methodName = object->GetMethodName(methodIndex, alias);
            check(object->FindMethod(methodName) == methodIndex, "Repeated method name lookup");
            releaseName(methodName);
            noAllocations();
            const auto propertyName = object->GetPropName(propertyIndex, alias);
            check(object->FindProp(propertyName) == propertyIndex, "Repeated property name lookup");
            releaseName(propertyName);
            noAllocations();
        }
        WCHAR_T* extension = nullptr;
        check(object->RegisterExtensionAs(&extension), "Repeated extension registration");
        releaseName(extension);
        noAllocations();
        {
            Value value(host.memory);
            check(object->GetParamDefValue(connectMethod, 4, &value.value) && value.text().empty(), "Repeated optional fingerprint");
        }
        noAllocations();
        for (const auto method : {L"GetFile", L"MoveFile", L"Stat", L"PutFile", L"PutFiles"}) {
            Value value(host.memory);
            const auto index = object->FindMethod(method);
            check(object->GetParamDefValue(index, object->GetNParams(index) - 1, &value.value) &&
                value.value.vt == VTYPE_BOOL && !value.value.bVal, "Repeated optional boolean");
        }
        noAllocations();
        auto timeout = number(2);
        check(object->SetPropVal(timeoutProperty, &timeout), "Repeated timeout update");
        allocationFailure([&] {
            Value value(host.memory);
            check(!object->GetPropVal(object->FindProp(L"Version"), &value.value) &&
                value.value.vt == VTYPE_EMPTY, "Property allocation failure returned a value");
        });
        check(!host.property(L"LastError").text().empty(), "Allocation failure diagnostic missing");
        noAllocations();
        allocationFailure([&] {
            Value value(host.memory);
            check(!object->GetParamDefValue(connectMethod, 4, &value.value) &&
                value.value.vt == VTYPE_EMPTY, "Default value allocation failure returned a value");
        });
        allocationFailure([&] {
            check(!object->GetMethodName(methodIndex, iteration % 2), "Method name allocation failure ignored");
        });
        allocationFailure([&] {
            check(!object->GetPropName(propertyIndex, iteration % 2), "Property name allocation failure ignored");
        });
        allocationFailure([&] {
            WCHAR_T* name = nullptr;
            check(!object->RegisterExtensionAs(&name) && name == nullptr, "Extension allocation failure returned a name");
        });
        host.fails(L"ListFiles", {text(L"/not-connected")});
        const auto previousError = host.property(L"LastError").text();
        const auto previousDetails = host.property(L"LastErrorDetails").text();
        for (const auto property : {L"HostKeyFingerprint", L"LastError", L"LastErrorDetails"}) {
            allocationFailure([&] {
                Value value(host.memory);
                check(!object->GetPropVal(object->FindProp(property), &value.value) &&
                    value.value.vt == VTYPE_EMPTY, "Failed diagnostic read returned a value");
            });
            check(host.property(L"LastError").text() == previousError &&
                host.property(L"LastErrorDetails").text() == previousDetails, "Failed property read replaced the diagnosed error");
            noAllocations();
        }
        timeout = number(1.5);
        check(!object->SetPropVal(timeoutProperty, &timeout), "Repeated invalid timeout accepted");
        check(host.property(L"LastErrorDetails").text().find(L"\"operation\":\"SetTimeout\"") != std::wstring::npos,
            "Failed property write lost its diagnostic context");
        noAllocations();
        check(object->CallAsProc(object->FindMethod(L"Disconnect"), nullptr, 0), "Repeated procedure call failed");
        check(host.property(L"LastError").text().empty() && host.property(L"LastErrorDetails").text() == L"{}",
            "Repeated Disconnect did not clear diagnostics");
        noAllocations();
    }
    object->Done();
    object->Done();
    check(object->Init(&host.platform) && object->setMemManager(&host.memory), "Reinitialize after repeated Done");
    noAllocations();
}
