#include "log.h"

#include <stdio.h>
#include <windows.h>

void PrintfMsg(const wchar_t *fmt, ...) {
  // Calculate buffer size
  va_list args;
  va_start(args, fmt);
  int count = _vscwprintf(fmt, args);
  va_end(args);
  if (count < 0) {
#ifdef _DEBUG
    __debugbreak();
#endif
    return;
  }
  count += 2;

  // Format string
  wchar_t *buffer = (wchar_t *)malloc(sizeof(wchar_t) * count);
  if (!buffer) {
#ifdef _DEBUG
    __debugbreak();
#endif
    return;
  }
  va_start(args, fmt);
  vswprintf_s(buffer, count, fmt, args);
  va_end(args);
  buffer[count - 2] = '\n';
  buffer[count - 1] = '\0';
  
  // Output message
  OutputDebugString(buffer);

  free(buffer);
}
