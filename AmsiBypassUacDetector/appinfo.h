#pragma once

#include <windows.h>

// NOTE: The following structures are based on reverse engineering and verified
// on Windows 7 ~ Windows 11 24H2

enum ELEVATION_REASON {};  // Name in PDB
enum CONSENTUI_PROMPT_TYPE {
  CONSENTUI_PROMPT_AUTO_APPROVAL = 1,
  CONSENTUI_PROMPT_CONFIRMATION_REQUIRED = 2,
  CONSENTUI_PROMPT_PASSWORD_REQUIRED = 3,
};  // Name in PDB, enum values guessed by me
enum CONSENTUI_REQUEST_TYPE {
  CONSENTUI_REQUEST_EXE = 0,
  CONSENTUI_REQUEST_COM = 1,
  CONSENTUI_REQUEST_MSI = 2,
  CONSENTUI_REQUEST_AX = 3,
  // Not sure where 4 went
  CONSENTUI_REQUEST_PACKAGED_APP = 5,
};  // Type names guessed by me
struct CONSENTUI_RETURN_PARAM {
  HANDLE hToken;  // Seems to be a value, login token returned by consent.exe,
                  // possibly returned after password confirmation is required
                  // by consent.exe
};  // Name in PDB

struct CONSENTUI_PARAM_HEADER_7600 {
  DWORD dwSize;  // +0x00
  CONSENTUI_REQUEST_TYPE dwRequestType;
  CONSENTUI_PROMPT_TYPE
  dwPromptType;  // This is the registry policy: 2 is the default, no
                 // password required, confirmation is sufficient; 3
                 // requires a password; 1 is automatic approval without a
                 // popup; values greater than or equal to 4 are likely
                 // invalid. If the program itself can be automatically
                 // elevated, this parameter is ignored; if the program
                 // requires approval, this parameter is useful.
  // DWORD __Padding1;

  HANDLE hWnd;  // +0x10
  HANDLE hToken;

  ELEVATION_REASON
  dwReason;  // +0x20, from CheckElevation and appinfo internal logic:
             // exe/uwp double-click run is 2, automatically elevated COM
             // component is 4, exe/uwp right-click run as administrator is
             // 6, uwp in some cases is 8 (seems to occur when
             // system-built-in uwp is right-clicked to run as
             // administrator), AiLaunchConsentUI also has a check for
             // whether it equals 9 (not sure under what circumstances this
             // occurs)
  DWORD dwTokenSessionId;
  HANDLE hSessionLockMutex;

  DWORD dwConsentFlags;  // +0x30
  // DWORD __Padding2;
  // CHAR lpCvStr[0x81];  // +0x38 Tracking related content:
  //                      // https://github.com/microsoft/CorrelationVector
  //// CHAR __Padding3[7]; // +0xB9

  CONSENTUI_RETURN_PARAM* lpReturnParam;  // +0xC0

  union {
    struct {
      HANDLE hApplicationFile;  // +0xC8 Guessed name
      LPWSTR
      lpwszApplicationNameOrCommandLine;  // +0xD0 Guessed name, value is
                                          // 0xF8, offset of
                                          // ApplicationNameOrCommandLine,
                                          // if ApplicationName exists,
                                          // use ApplicationName,
                                          // otherwise use CommandLine
      LPWSTR
      lpwszApplicationName;      // +0xD8 Name from amsi, executable file path
      LPWSTR lpwszCommandLine;   // +0xE0 Name from amsi, original command line
      LPWSTR lpwszDLLParameter;  // +0xE8 Name from amsi, if it's mmc.exe and an
                                 // msc is specified, this is the value of the
                                 // second parameter parsed as a full path,
                                 // e.g., C:\windows\system32\xx.msc
      ULONG ulRequestorProcessId;
    } ExeInfo;

    struct {
      LPWSTR lpwszFriendlyName;   // +0xC8 Name from telemetry call
      LPWSTR lpwszServerBinary;   // +0xD0 Name from amsi
      LPWSTR lpwszIconReference;  // +0xD8 Name from telemetry call
      LPWSTR lpwszRequestor;      // +0xE0 Name from amsi
      GUID Clsid;                 // +0xE8 Name from amsi
    } ComInfo;

    struct {
      DWORD dwAction;  // +0xC8 Name from telemetry call
      // DWORD __Padding4;
      LPWSTR lpwszProductName;    // +0xD0 Name from amsi
      LPWSTR lpwszVersion;        // Name from amsi
      LPWSTR lpwszLanguage;       // +0xE0 Name from amsi
      LPWSTR lpwszManufacturer;   // Name from amsi
      LPWSTR lpwszPackagePath;    // +0xF0 Name from amsi
      LPWSTR lpwszPackageSource;  // Name from amsi
      ULONG ulUpdates;            // +0x100 Name from amsi
      // ULONG __Padding5;
      LPWSTR* ppwszUpdates;        // +0x108 size_is(ulUpdates, ) Name from amsi
      LPWSTR* ppwszUpdateSources;  // +0x110 size_is(ulUpdates, ) Name from amsi
    } MsiInfo;

    struct {
      LPWSTR lpwszLocalInstallPath;  // +0xC8 Name from amsi
      LPWSTR lpwszSourceURL;         // +0xD0 Name from amsi
    } AxInfo;

    struct {
      LPWSTR lpwszApplicationName;  // +0xC8 Name from amsi
      LPWSTR lpwszCommandLine;      // +0xD0 Name from amsi
      LPWSTR lpPackageFamilyName;   // Name from amsi
      LPWSTR lpApplicationId;       // +0xE0 Name from amsi
      ULONG ulRequestorProcessId;   // Name from amsi
    } PackagedAppInfo;
  } RequestType;  // +0xC8 Name from amsi
};

struct CONSENTUI_PARAM_HEADER_26100 {
  DWORD dwSize;  // +0x00
  CONSENTUI_REQUEST_TYPE dwRequestType;
  CONSENTUI_PROMPT_TYPE
  dwPromptType;  // This is the registry policy: 2 is the default, no
                 // password required, confirmation is sufficient; 3
                 // requires a password; 1 is automatic approval without a
                 // popup; values greater than or equal to 4 are likely
                 // invalid. If the program itself can be automatically
                 // elevated, this parameter is ignored; if the program
                 // requires approval, this parameter is useful.
  // DWORD __Padding1;

  HANDLE hWnd;  // +0x10
  HANDLE hToken;

  ELEVATION_REASON
  dwReason;  // +0x20, from CheckElevation and appinfo internal logic:
             // exe/uwp double-click run is 2, automatically elevated COM
             // component is 4, exe/uwp right-click run as administrator is
             // 6, uwp in some cases is 8 (seems to occur when
             // system-built-in uwp is right-clicked to run as
             // administrator), AiLaunchConsentUI also has a check for
             // whether it equals 9 (not sure under what circumstances this
             // occurs)
  DWORD dwTokenSessionId;
  HANDLE hSessionLockMutex;

  DWORD dwConsentFlags;  // +0x30
  DWORD __Padding2;
  CHAR lpCvStr[0x81];  // +0x38 Tracking related content:
                       // https://github.com/microsoft/CorrelationVector
  // CHAR __Padding3[7]; // +0xB9

  CONSENTUI_RETURN_PARAM* lpReturnParam;  // +0xC0

  union {
    struct {
      HANDLE hApplicationFile;  // +0xC8 Guessed name
      LPWSTR
      lpwszApplicationNameOrCommandLine;  // +0xD0 Guessed name, value is
                                          // 0xF8, offset of
                                          // ApplicationNameOrCommandLine,
                                          // if ApplicationName exists,
                                          // use ApplicationName,
                                          // otherwise use CommandLine
      LPWSTR
      lpwszApplicationName;      // +0xD8 Name from amsi, executable file path
      LPWSTR lpwszCommandLine;   // +0xE0 Name from amsi, original command line
      LPWSTR lpwszDLLParameter;  // +0xE8 Name from amsi, if it's mmc.exe and an
                                 // msc is specified, this is the value of the
                                 // second parameter parsed as a full path,
                                 // e.g., C:\windows\system32\xx.msc
      ULONG ulRequestorProcessId;
    } ExeInfo;

    struct {
      LPWSTR lpwszFriendlyName;   // +0xC8 Name from telemetry call
      LPWSTR lpwszServerBinary;   // +0xD0 Name from amsi
      LPWSTR lpwszIconReference;  // +0xD8 Name from telemetry call
      LPWSTR lpwszRequestor;      // +0xE0 Name from amsi
      GUID Clsid;                 // +0xE8 Name from amsi
    } ComInfo;

    struct {
      DWORD dwAction;  // +0xC8 Name from telemetry call
      // DWORD __Padding4;
      LPWSTR lpwszProductName;    // +0xD0 Name from amsi
      LPWSTR lpwszVersion;        // Name from amsi
      LPWSTR lpwszLanguage;       // +0xE0 Name from amsi
      LPWSTR lpwszManufacturer;   // Name from amsi
      LPWSTR lpwszPackagePath;    // +0xF0 Name from amsi
      LPWSTR lpwszPackageSource;  // Name from amsi
      ULONG ulUpdates;            // +0x100 Name from amsi
      // ULONG __Padding5;
      LPWSTR* ppwszUpdates;        // +0x108 size_is(ulUpdates, ) Name from amsi
      LPWSTR* ppwszUpdateSources;  // +0x110 size_is(ulUpdates, ) Name from amsi
    } MsiInfo;

    struct {
      LPWSTR lpwszLocalInstallPath;  // +0xC8 Name from amsi
      LPWSTR lpwszSourceURL;         // +0xD0 Name from amsi
    } AxInfo;

    struct {
      LPWSTR lpwszApplicationName;  // +0xC8 Name from amsi
      LPWSTR lpwszCommandLine;      // +0xD0 Name from amsi
      LPWSTR lpPackageFamilyName;   // Name from amsi
      LPWSTR lpApplicationId;       // +0xE0 Name from amsi
      ULONG ulRequestorProcessId;   // Name from amsi
    } PackagedAppInfo;
  } RequestType;  // +0xC8 Name from amsi
};

BOOL DumpConsentUIParam(DWORD consentPID);
