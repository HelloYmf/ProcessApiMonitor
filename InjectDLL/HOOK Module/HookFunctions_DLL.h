#pragma once
#include <Windows.h>

#include "../File Module/Cfile_DLL.h"

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

//ÉèÖÃIAT HOOK
BOOL SetIATHook(DWORD oldFunAddr, DWORD newFunAddr);

//Ð¶ÔØIAT HOOK
BOOL UnSetIATHook(DWORD oldFunAddr, DWORD newFunAddr);

//ÉèÖÃInline HOOK
BOOL SetInlineHOOK(DWORD dwHookAddr, DWORD dwHookLen);

//Ð¶ÔØInline HOOK
BOOL UnSetInlineHOOK();

