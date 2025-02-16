#pragma once

#include <amsi.h>
#include <wrl.h>

// Use a smaller GUID to increase priority
class DECLSPEC_UUID("01474503-71B8-4E19-8F70-2C4B98D2EA74")
    SampleAmsiUacProvider
    : public Microsoft::WRL::RuntimeClass<
          Microsoft::WRL::RuntimeClassFlags<Microsoft::WRL::ClassicCom>,
          IAntimalwareUacProvider, Microsoft::WRL::FtmBase> {
 public:
  IFACEMETHOD(QueryInterface)(_In_ REFIID riid, _COM_Outptr_ void** ppvObject);
  IFACEMETHOD(UacScan)(_In_ LPAMSI_UAC_REQUEST_CONTEXT context,
                       _Out_ AMSI_RESULT* result);
  IFACEMETHOD(DisplayName)(_Outptr_ LPWSTR* displayName);
};

CoCreatableClass(SampleAmsiUacProvider);
