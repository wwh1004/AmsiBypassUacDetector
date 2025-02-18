#include "amsiuacprov.h"

#include <psapi.h>

#include <ctime>
#include <functional>
#include <unordered_map>

#include "appinfo.h"
#include "log.h"
#include "ntdll.h"
#include "patcher.h"

namespace {
std::unordered_map<uint32_t, std::time_t> patchedConsents{};

NTSTATUS EnumerateProcesses(
    std::function<BOOL(HANDLE)> callback,
    ACCESS_MASK desiredAccess = PROCESS_QUERY_LIMITED_INFORMATION) {
  HANDLE hProcess = NULL;
  HANDLE hNewProcess = NULL;

  // Get the first process
  NTSTATUS status = NtGetNextProcess(hProcess, desiredAccess, 0, 0, &hProcess);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  while (true) {
    if (!callback(hProcess)) {
      break;
    }

    // Get the next process and close the previous one
    status = NtGetNextProcess(hProcess, desiredAccess, 0, 0, &hNewProcess);
    CloseHandle(hProcess);
    if (NT_SUCCESS(status)) {
      hProcess = hNewProcess;
    } else {
      break;
    }
  }

  return status;
}

std::vector<uint32_t> GetProcesses() {
  std::vector<uint32_t> processes;
  EnumerateProcesses([&processes](HANDLE hProcess) {
    DWORD pid = GetProcessId(hProcess);
    processes.push_back(pid);
    return TRUE;
  });
  return processes;
}

std::vector<uint32_t> GetProcessesByName(const wchar_t* processName) {
  std::vector<uint32_t> processes;
  EnumerateProcesses([&processes, processName](HANDLE hProcess) {
    BYTE buffer[1024]{};
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessImageFileName,
                                                buffer, sizeof(buffer), NULL);
    if (NT_SUCCESS(status) && ((PUNICODE_STRING)buffer)->Buffer) {
      LPWSTR imageFileName = ((PUNICODE_STRING)buffer)->Buffer;
      LPWSTR fileName = wcsrchr(imageFileName, L'\\');
      if (fileName) {
        fileName++;
        if (_wcsicmp(fileName, processName) == 0) {
          DWORD pid = GetProcessId(hProcess);
          processes.push_back(pid);
        }
      }
    }
    return TRUE;
  });
  return processes;
}

void PatchConsent() {
  auto consents = GetProcessesByName(L"consent.exe");
  if (consents.empty()) {
    TRACEF(L"consent.exe not found");
    return;
  }

  for (auto pid : consents) {
    auto it = patchedConsents.find(pid);
    if (it != patchedConsents.end() && std::time(nullptr) - it->second < 5) {
      TRACEF(L"consent.exe already patched, skipping");
      continue;
    }

    BOOL b = PatchAmsiPPLVerification(pid);
    if (!b) {
      PRINTF(L"Failed to patch consent.exe");
      continue;
    }

    PRINTF(L"consent.exe patched");
    patchedConsents[pid] = std::time(nullptr);
  }
}

BOOL CheckMasqueradedProcess(HANDLE hProcess) {
  // Get the command line of the process
  BYTE commandLineBuffer[1024]{};
  PUNICODE_STRING commandLineString = (PUNICODE_STRING)commandLineBuffer;
  NTSTATUS status = NtQueryInformationProcess(
      hProcess, ProcessCommandLineInformation, commandLineBuffer,
      sizeof(commandLineBuffer), NULL);

  // Just skip the process if we cannot get the command line
  if (!NT_SUCCESS(status) || !commandLineString->Buffer) {
    return FALSE;
  }
  LPWSTR commandLine = commandLineString->Buffer;

  // Get the initial process file name
  BYTE imageFileNameBuffer[1024]{};
  PUNICODE_STRING imageFileNameString = (PUNICODE_STRING)imageFileNameBuffer;
  status = NtQueryInformationProcess(hProcess, ProcessImageFileName,
                                     imageFileNameBuffer,
                                     sizeof(imageFileNameBuffer), NULL);

  // Just skip the process if we cannot get the image file name
  if (!NT_SUCCESS(status) || !imageFileNameString->Buffer) {
    return FALSE;
  }
  LPWSTR imageFileName = imageFileNameString->Buffer;

  // Lowercase the command line and image file name
  _wcslwr_s(commandLine, wcslen(commandLine) + 1);
  _wcslwr_s(imageFileName, wcslen(imageFileName) + 1);

  // TODO: more checks
  if (wcsstr(commandLine, L"explorer.exe") &&
      !wcsstr(imageFileName, L"explorer.exe")) {
    PRINTF(
        L"Masqueraded process found: pid = %d, commandLine = %s, "
        L"imageFileName = %s",
        GetProcessId(hProcess), commandLine, imageFileName);
    return TRUE;
  }

  return FALSE;
}

BOOL CheckMasqueradedProcesses() {
  BOOL found = FALSE;
  EnumerateProcesses([&found](HANDLE hProcess) {
    found |= CheckMasqueradedProcess(hProcess);
    return TRUE;
  });
  return found;
}

void DumpUacRequet(LPAMSI_UAC_REQUEST_CONTEXT context) {
  switch (context->Type) {
    case AMSI_UAC_REQUEST_TYPE_EXE: {
      LPAMSI_UAC_REQUEST_EXE_INFO exeInfo = &context->RequestType.ExeInfo;
      PRINTF(
          L"UAC request for EXE: processId = %d, trustState = %d, autoElevate "
          L"= %d, applicationName = %s, commandLine = %s, dllParameter = %s",
          context->ulRequestorProcessId, context->UACTrustState,
          context->bAutoElevateRequest, exeInfo->lpwszApplicationName,
          exeInfo->lpwszCommandLine, exeInfo->lpwszDLLParameter);
      break;
    }
    case AMSI_UAC_REQUEST_TYPE_COM: {
      LPAMSI_UAC_REQUEST_COM_INFO comInfo = &context->RequestType.ComInfo;
      WCHAR clsidString[40];
      (void)StringFromGUID2(comInfo->Clsid, clsidString,
                            ARRAYSIZE(clsidString));
      PRINTF(
          L"UAC request for COM: processId = %d, trustState = %d, autoElevate "
          L"= %d, serverBinary = %s, requestor = %s, clsid = %s",
          context->ulRequestorProcessId, context->UACTrustState,
          context->bAutoElevateRequest, comInfo->lpwszServerBinary,
          comInfo->lpwszRequestor, clsidString);
      break;
    }
    case AMSI_UAC_REQUEST_TYPE_MSI: {
      LPAMSI_UAC_REQUEST_MSI_INFO msiInfo = &context->RequestType.MsiInfo;
      PRINTF(
          L"UAC request for MSI: processId = %d, trustState = %d, autoElevate "
          L"= %d, action = %d, productName = %s, version = %s, language = %s, "
          L"manufacturer = %s, packagePath = %s, packageSource = %s, updates = "
          L"%d",
          context->ulRequestorProcessId, context->UACTrustState,
          context->bAutoElevateRequest, msiInfo->MsiAction,
          msiInfo->lpwszProductName, msiInfo->lpwszVersion,
          msiInfo->lpwszLanguage, msiInfo->lpwszManufacturer,
          msiInfo->lpwszPackagePath, msiInfo->lpwszPackageSource,
          msiInfo->ulUpdates);
      break;
    }
    case AMSI_UAC_REQUEST_TYPE_AX: {
      LPAMSI_UAC_REQUEST_AX_INFO axInfo = &context->RequestType.ActiveXInfo;
      PRINTF(
          L"UAC request for ActiveX: processId = %d, trustState = %d, "
          L"autoElevate = %d, localInstallPath = %s, sourceURL = %s",
          context->ulRequestorProcessId, context->UACTrustState,
          context->bAutoElevateRequest, axInfo->lpwszLocalInstallPath,
          axInfo->lpwszSourceURL);
      break;
    }
    case AMSI_UAC_REQUEST_TYPE_PACKAGED_APP: {
      LPAMSI_UAC_REQUEST_PACKAGED_APP_INFO packagedAppInfo =
          &context->RequestType.PackagedAppInfo;
      PRINTF(
          L"UAC request for Packaged App: processId = %d, trustState = %d, "
          L"autoElevate = %d, applicationName = %s, commandLine = %s, "
          L"packageFamilyName = %s, applicationId = %s",
          context->ulRequestorProcessId, context->UACTrustState,
          context->bAutoElevateRequest, packagedAppInfo->lpwszApplicationName,
          packagedAppInfo->lpwszCommandLine,
          packagedAppInfo->lpPackageFamilyName,
          packagedAppInfo->lpApplicationId);
      break;
    }
    default:
      PRINTF(L"Unknown UAC request type: %d", context->Type);
      break;
  }
}
}  // namespace

HRESULT SampleAmsiUacProvider::QueryInterface(_In_ REFIID riid,
                                              _COM_Outptr_ void** ppvObject) {
  // TRACEF(L"SampleAmsiUacProvider::QueryInterface called");
  if (riid == __uuidof(IAntimalwareUacProvider)) {
    PatchConsent();
  }
  return RuntimeClass::QueryInterface(riid, ppvObject);
}

HRESULT SampleAmsiUacProvider::UacScan(_In_ LPAMSI_UAC_REQUEST_CONTEXT context,
                                       _Out_ AMSI_RESULT* result) {
  TRACEF(L"SampleAmsiUacProvider::UacScan called");

  DumpUacRequet(context);

  DWORD clientPID = 0;
  if (I_RpcBindingInqLocalClientPID(NULL, &clientPID) == RPC_S_OK) {
    TRACEF(L"SampleAmsiUacProvider::UacScan: clientPID = %d", clientPID);
    DumpConsentUIParam(clientPID);
  }

  // OPTIMIZATION: Only check masqueraded processes if the request is
  // auto-elevate
  if (context->bAutoElevateRequest) {
    clock_t start = clock();
    *result = CheckMasqueradedProcesses() ? AMSI_RESULT_DETECTED
                                          : AMSI_RESULT_NOT_DETECTED;
    TRACEF(L"CheckMasqueradedProcesses took %d ms", clock() - start);
  } else {
    *result = AMSI_RESULT_NOT_DETECTED;
  }

  return S_OK;
}

HRESULT SampleAmsiUacProvider::DisplayName(_Outptr_ LPWSTR* displayName) {
  constexpr auto DisplayName = L"Sample AMSI UAC Provider";

  TRACEF(L"SampleAmsiUacProvider::DisplayName called");

  *displayName =
      (LPWSTR)CoTaskMemAlloc((wcslen(DisplayName) + 1) * sizeof(WCHAR));
  if (!*displayName) {
    return E_OUTOFMEMORY;
  }

  wcscpy_s(*displayName, wcslen(DisplayName) + 1, DisplayName);
  return S_OK;
}
