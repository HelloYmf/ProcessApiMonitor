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

//…Ë÷√IAT HOOK
BOOL SetIATHook(DWORD oldFunAddr, DWORD newFunAddr);

//–∂‘ÿIAT HOOK
BOOL UnSetIATHook(DWORD oldFunAddr, DWORD newFunAddr);

//…Ë÷√Inline HOOK
BOOL SetInlineHOOK(DWORD dwHookAddr, DWORD dwHookLen);

//–∂‘ÿInline HOOK
BOOL UnSetInlineHOOK();

