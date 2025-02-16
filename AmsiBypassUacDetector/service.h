#pragma once

#include <windows.h>

void WINAPI ServiceMain(__in DWORD dwArgc,
                        __in_ecount(dwArgc) LPWSTR *pwszArgv);
