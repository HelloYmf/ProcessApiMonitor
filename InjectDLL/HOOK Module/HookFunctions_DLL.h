#pragma once
#include <Windows.h>

#include "../File/Cfile_DLL.h"

int WINAPI myMessageBoxA(
	HWND   hWnd,
	LPCSTR lpText,
	LPCSTR lpCaption,
	UINT   uType
);

HANDLE WINAPI myCreateFileA(
	LPCSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
);

//����IAT HOOK
BOOL SetIATHook(DWORD oldFunAddr, DWORD newFunAddr);

//ж��IAT HOOK
BOOL UnSetIATHook(DWORD oldFunAddr, DWORD newFunAddr);

//����Inline HOOK
BOOL SetInlineHOOK(DWORD dwHookAddr, DWORD dwHookLen);

//ж��Inline HOOK
BOOL UnSetInlineHOOK();

