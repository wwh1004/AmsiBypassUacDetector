#pragma once

void PrintfMsg(const wchar_t *fmt, ...);

#define PRINTF(a, ...) PrintfMsg(a, ##__VA_ARGS__)

#ifdef _DEBUG
#define _TRACE
#endif

#ifdef _TRACE
#define TRACEF(a, ...) PrintfMsg("[DBG] " a, ##__VA_ARGS__)
#else
#define TRACEF(a, ...)
#endif
