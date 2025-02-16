#include <stdio.h>
#include <windows.h>

#include "register.h"
#include "service.h"

namespace {
void PrintUsage() {
  printf("Usage: <This EXE> [/RegisterServer][/UnregisterServer]\n");
}
}  // namespace

int wmain(int argc, wchar_t* argv[]) {
  // Parse the command line, several cases:
  //
  // 1. User runs this exe with RegisterServer/UnregisterServer to
  // register/unregister it
  // 2. COM activate this exe with "Embedding" option,
  // 3. SCM launches this exe from a service control program such as "net start
  // <ServiceName>"
  // 4. User launches this exe directly.

  HRESULT hr = E_INVALIDARG;
  bool fStartService = false;
  if (argc > 1) {
    wchar_t szTokens[] = L"-/";
    LPWSTR pszNextToken;
    LPWSTR pszToken = wcstok_s(argv[1], szTokens, &pszNextToken);
    if (pszToken != nullptr) {
      if (_wcsicmp(pszToken, L"RegisterServer") == 0) {
        hr = ExeRegisterServer();
        printf("RegisterServer done, hr = %08X\n", hr);
      } else if (_wcsicmp(pszToken, L"UnregisterServer") == 0) {
        hr = ExeUnregisterServer();
        printf("UnregisterServer done, hr = %08X\n", hr);
      } else if (_wcsicmp(pszToken, L"Embedding") == 0) {
        // COM started us, we will start our service.
        hr = S_OK;
        fStartService = true;
      } else {
        printf("Unknown switch.\n");
        PrintUsage();
      }
    } else {
      printf("Unknown parameter.\n");
      PrintUsage();
    }
  } else {
    // User launches our exe, or SCM launches us. We will start our service.
    hr = S_OK;
    fStartService = true;
  }

  // Ask SCM to start our service.
  if (fStartService) {
    SERVICE_TABLE_ENTRY rgServiceTable[2] = {
        0};  // Only need 1 entry and then the trailing nullptr.
    rgServiceTable[0].lpServiceName = const_cast<LPWSTR>(SERVICE_NAME);
    rgServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;
    hr = StartServiceCtrlDispatcher(rgServiceTable)
             ? S_OK
             : HRESULT_FROM_WIN32(GetLastError());
  }

  return (SUCCEEDED(hr) ? 0 : hr);
}
