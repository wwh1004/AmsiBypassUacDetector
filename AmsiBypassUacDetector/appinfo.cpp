#include "appinfo.h"

#include <stdint.h>
#include <stdio.h>

#include "log.h"
#include "ntdll.h"

namespace {
BOOL ParseConsentCommandLine(DWORD consentPID, DWORD& appinfoPID, DWORD& size,
                             PVOID& address) {
  appinfoPID = 0;
  size = 0;
  address = NULL;
  BOOL bRet = FALSE;
  HANDLE hProcess =
      OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, consentPID);
  if (hProcess) {
    // Get the command line of the process
    BYTE commandLineBuffer[1024]{};
    PUNICODE_STRING commandLineString = (PUNICODE_STRING)commandLineBuffer;
    NTSTATUS status = NtQueryInformationProcess(
        hProcess, ProcessCommandLineInformation, commandLineBuffer,
        sizeof(commandLineBuffer), NULL);
    if (NT_SUCCESS(status) && commandLineString->Buffer) {
      int argc;
      wchar_t** argv = CommandLineToArgvW(commandLineString->Buffer, &argc);
      if (argv) {
        if (argc >= 4) {
          swscanf_s(argv[1], L"%u", &appinfoPID);
          swscanf_s(argv[2], L"%u", &size);
          swscanf_s(argv[3], L"%p", &address);
          bRet = appinfoPID && size && address;
          if (!bRet) {
            PRINTF(L"Failed to parse appinfo PID, size, or address");
          }
        } else {
          PRINTF(L"Invalid command line of process %d", consentPID);
        }
        LocalFree(argv);
      } else {
        PRINTF(L"Failed to parse command line of process %d", consentPID);
      }
    } else {
      PRINTF(L"Failed to get command line of process %d", consentPID);
    }
    CloseHandle(hProcess);
  }
  return bRet;
}

BOOL ReadAppinfoParam(DWORD consentPID, PVOID& buffer) {
  // Get the address of CONSENTUI_PARAM_HEADER structure
  DWORD appinfoPID = 0;
  DWORD size = 0;
  PVOID address = NULL;
  if (!ParseConsentCommandLine(consentPID, appinfoPID, size, address)) {
    PRINTF(L"Failed to parse consent command line");
    return FALSE;
  }
  TRACEF(L"ReadAppinfoParam: appinfoPID = %d, size = %d, address = %p",
         appinfoPID, size, address);

  BOOL bRet = FALSE;
  if (buffer = malloc(size)) {
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, appinfoPID);
    if (hProcess) {
      SIZE_T bytesRead = 0;
      if (ReadProcessMemory(hProcess, address, buffer, size, &bytesRead) &&
          bytesRead == size) {
        bRet = TRUE;
      } else {
        PRINTF(L"Failed to read appinfo param from process %d", appinfoPID);
      }
      CloseHandle(hProcess);
    }
  }
  return bRet;
}

template <typename T>
void FixParamPointersImpl(T* param) {
  switch (param->dwRequestType) {
    case CONSENTUI_REQUEST_EXE: {
      auto exeInfo = &param->RequestType.ExeInfo;
      exeInfo->lpwszApplicationNameOrCommandLine =
          (LPWSTR)((PBYTE)param +
                   (SIZE_T)exeInfo->lpwszApplicationNameOrCommandLine);
      exeInfo->lpwszApplicationName =
          (LPWSTR)((PBYTE)param + (SIZE_T)exeInfo->lpwszApplicationName);
      exeInfo->lpwszCommandLine =
          (LPWSTR)((PBYTE)param + (SIZE_T)exeInfo->lpwszCommandLine);
      exeInfo->lpwszDLLParameter =
          (LPWSTR)((PBYTE)param + (SIZE_T)exeInfo->lpwszDLLParameter);
      break;
    }
    case CONSENTUI_REQUEST_COM: {
      auto comInfo = &param->RequestType.ComInfo;
      comInfo->lpwszFriendlyName =
          (LPWSTR)((PBYTE)param + (SIZE_T)comInfo->lpwszFriendlyName);
      comInfo->lpwszServerBinary =
          (LPWSTR)((PBYTE)param + (SIZE_T)comInfo->lpwszServerBinary);
      comInfo->lpwszIconReference =
          (LPWSTR)((PBYTE)param + (SIZE_T)comInfo->lpwszIconReference);
      comInfo->lpwszRequestor =
          (LPWSTR)((PBYTE)param + (SIZE_T)comInfo->lpwszRequestor);
      break;
    }
    case CONSENTUI_REQUEST_MSI: {
      auto msiInfo = &param->RequestType.MsiInfo;
      msiInfo->lpwszProductName =
          (LPWSTR)((PBYTE)param + (SIZE_T)msiInfo->lpwszProductName);
      msiInfo->lpwszVersion =
          (LPWSTR)((PBYTE)param + (SIZE_T)msiInfo->lpwszVersion);
      msiInfo->lpwszLanguage =
          (LPWSTR)((PBYTE)param + (SIZE_T)msiInfo->lpwszLanguage);
      msiInfo->lpwszManufacturer =
          (LPWSTR)((PBYTE)param + (SIZE_T)msiInfo->lpwszManufacturer);
      msiInfo->lpwszPackagePath =
          (LPWSTR)((PBYTE)param + (SIZE_T)msiInfo->lpwszPackagePath);
      msiInfo->lpwszPackageSource =
          (LPWSTR)((PBYTE)param + (SIZE_T)msiInfo->lpwszPackageSource);
      msiInfo->ppwszUpdates =
          (LPWSTR*)((PBYTE)param + (SIZE_T)msiInfo->ppwszUpdates);
      msiInfo->ppwszUpdateSources =
          (LPWSTR*)((PBYTE)param + (SIZE_T)msiInfo->ppwszUpdateSources);
      break;
    }
    case CONSENTUI_REQUEST_AX: {
      auto axInfo = &param->RequestType.AxInfo;
      axInfo->lpwszLocalInstallPath =
          (LPWSTR)((PBYTE)param + (SIZE_T)axInfo->lpwszLocalInstallPath);
      axInfo->lpwszSourceURL =
          (LPWSTR)((PBYTE)param + (SIZE_T)axInfo->lpwszSourceURL);
      break;
    }
    case CONSENTUI_REQUEST_PACKAGED_APP: {
      auto packagedAppInfo = &param->RequestType.PackagedAppInfo;
      packagedAppInfo->lpwszApplicationName =
          (LPWSTR)((PBYTE)param +
                   (SIZE_T)packagedAppInfo->lpwszApplicationName);
      packagedAppInfo->lpwszCommandLine =
          (LPWSTR)((PBYTE)param + (SIZE_T)packagedAppInfo->lpwszCommandLine);
      packagedAppInfo->lpPackageFamilyName =
          (LPWSTR)((PBYTE)param + (SIZE_T)packagedAppInfo->lpPackageFamilyName);
      packagedAppInfo->lpApplicationId =
          (LPWSTR)((PBYTE)param + (SIZE_T)packagedAppInfo->lpApplicationId);
      break;
    }
    default:
      PRINTF(L"Unknown consent param UAC request type %d",
             param->dwRequestType);
      break;
  }
}

template <typename T>
void DumpConsentUIParam(T* param) {
  switch (param->dwRequestType) {
    case CONSENTUI_REQUEST_EXE: {
      auto exeInfo = &param->RequestType.ExeInfo;
      PRINTF(
          L"Consent param UAC request for EXE: promptType = %d, hWnd = %p, "
          L"hToken = %p, reason = %d, sessionId = %d, hApplicationFile = %p, "
          L"lpwszApplicationNameOrCommandLine = %s, lpwszApplicationName = %s, "
          L"lpwszCommandLine = %s, lpwszDLLParameter = %s, "
          L"ulRequestorProcessId = %d",
          param->dwPromptType, param->hWnd, param->hToken, param->dwReason,
          param->dwTokenSessionId, exeInfo->hApplicationFile,
          exeInfo->lpwszApplicationNameOrCommandLine,
          exeInfo->lpwszApplicationName, exeInfo->lpwszCommandLine,
          exeInfo->lpwszDLLParameter, exeInfo->ulRequestorProcessId);
      break;
    }
    case CONSENTUI_REQUEST_COM: {
      auto comInfo = &param->RequestType.ComInfo;
      WCHAR clsidString[40];
      (void)StringFromGUID2(comInfo->Clsid, clsidString,
                            ARRAYSIZE(clsidString));
      PRINTF(
          L"Consent param UAC request for COM: promptType = %d, hWnd = %p, "
          L"hToken = %p, reason = %d, sessionId = %d, lpwszFriendlyName = %s, "
          L"lpwszServerBinary = %s, lpwszIconReference = %s, lpwszRequestor = "
          L"%s, Clsid = %s",
          param->dwPromptType, param->hWnd, param->hToken, param->dwReason,
          param->dwTokenSessionId, comInfo->lpwszFriendlyName,
          comInfo->lpwszServerBinary, comInfo->lpwszIconReference,
          comInfo->lpwszRequestor, clsidString);
      break;
    }
    case CONSENTUI_REQUEST_MSI: {
      auto msiInfo = &param->RequestType.MsiInfo;
      PRINTF(
          L"Consent param UAC request for MSI: promptType = %d, hWnd = %p, "
          L"hToken = %p, reason = %d, sessionId = %d, dwAction = %d, "
          L"lpwszProductName = %s, lpwszVersion = %s, lpwszLanguage = %s, "
          L"lpwszManufacturer = %s, lpwszPackagePath = %s, lpwszPackageSource "
          L"= %s, ulUpdates = %d",
          param->dwPromptType, param->hWnd, param->hToken, param->dwReason,
          param->dwTokenSessionId, msiInfo->dwAction, msiInfo->lpwszProductName,
          msiInfo->lpwszVersion, msiInfo->lpwszLanguage,
          msiInfo->lpwszManufacturer, msiInfo->lpwszPackagePath,
          msiInfo->lpwszPackageSource, msiInfo->ulUpdates);
      break;
    }
    case CONSENTUI_REQUEST_AX: {
      auto axInfo = &param->RequestType.AxInfo;
      PRINTF(
          L"Consent param UAC request for AX: promptType = %d, hWnd = %p, "
          L"hToken = %p, reason = %d, sessionId = %d, lpwszLocalInstallPath = "
          L"%s, lpwszSourceURL = %s",
          param->dwPromptType, param->hWnd, param->hToken, param->dwReason,
          param->dwTokenSessionId, axInfo->lpwszLocalInstallPath,
          axInfo->lpwszSourceURL);
      break;
    }
    case CONSENTUI_REQUEST_PACKAGED_APP: {
      auto packagedAppInfo = &param->RequestType.PackagedAppInfo;
      PRINTF(
          L"Consent param UAC request for Packaged App: promptType = %d, hWnd "
          L"= %p, hToken = %p, reason = %d, sessionId = %d, "
          L"lpwszApplicationName = %s, lpwszCommandLine = %s, "
          L"lpPackageFamilyName = %s, lpApplicationId = %s, "
          L"ulRequestorProcessId = %d",
          param->dwPromptType, param->hWnd, param->hToken, param->dwReason,
          param->dwTokenSessionId, packagedAppInfo->lpwszApplicationName,
          packagedAppInfo->lpwszCommandLine,
          packagedAppInfo->lpPackageFamilyName,
          packagedAppInfo->lpApplicationId,
          packagedAppInfo->ulRequestorProcessId);
      break;
    }
    default:
      PRINTF(L"Unknown consent param UAC request type %d",
             param->dwRequestType);
      break;
  }
}
}  // namespace

namespace {
constexpr uint32_t MakeSystemVersion(uint8_t major, uint8_t minor,
                                     uint16_t build) {
  return major << 24 | minor << 16 | build;
}

uint32_t GetSystemVersion() {
  uint32_t version = ((uint8_t)(*(uint32_t*)0x7FFE026C) << 24) |
                     ((uint8_t)(*(uint32_t*)0x7FFE0270) << 16);
  if (version >= 0x0A00)  // Windows 10
    version |= (uint16_t)(*(uint32_t*)0x7FFE0260);
  return version;
}
}  // namespace

BOOL DumpConsentUIParam(DWORD consentPID) {
  PVOID param = NULL;
  if (!ReadAppinfoParam(consentPID, param)) {
    PRINTF(L"Failed to read param from appinfo");
    return FALSE;
  }

  uint32_t version = GetSystemVersion();
  if (version >= MakeSystemVersion(10, 0, 26100)) {
    CONSENTUI_PARAM_HEADER_26100* param26100 =
        (CONSENTUI_PARAM_HEADER_26100*)param;
    FixParamPointersImpl(param26100);
    DumpConsentUIParam(param26100);
  } else if (version >= MakeSystemVersion(6, 1, 7600)) {
    CONSENTUI_PARAM_HEADER_7600* param7600 =
        (CONSENTUI_PARAM_HEADER_7600*)param;
    FixParamPointersImpl(param7600);
    DumpConsentUIParam(param7600);
  } else {
    PRINTF(L"Unsupported system version %08X", version);
  }

  free(param);

  return TRUE;
}
