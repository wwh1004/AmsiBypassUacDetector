#pragma once

#include <windows.h>

constexpr auto SERVICE_NAME = L"AmsiBypassUacDetector";
constexpr auto SERVICE_DISPLAY_NAME = SERVICE_NAME;
constexpr auto SERVICE_APPID = L"{8ADC695D-419B-44BF-A6D9-19532D5CE3BC}";

HRESULT ExeRegisterServer();
HRESULT ExeUnregisterServer();
