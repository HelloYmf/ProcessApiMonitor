#include "Process_DLL.h"

BOOL CreatePipe(HANDLE& hPipe)
{
	const char* g_pStrPipeName = "\\\\.\\pipe\\NamePipe_Fly";	//管道名称
	hPipe = CreateNamedPipe(g_pStrPipeName, PIPE_ACCESS_DUPLEX,
		PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
		PIPE_UNLIMITED_INSTANCES, 0, 0, NMPWAIT_WAIT_FOREVER, 0);
	
	return TRUE;
}

BOOL OpenPipe(HANDLE& hPipe, const char* PipeName)
{
	hPipe = CreateFile(PipeName, GENERIC_READ | GENERIC_WRITE, 0,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	return TRUE;
}

BOOL WaitConnectPipe(HANDLE& hPipe)
{
	if (ConnectNamedPipe(hPipe, NULL) != NULL)
	{
		MessageBox(NULL, "命名管道连接成功，开始通信！", "[控制端]", MB_OK);
		return TRUE;
	}
	else
	{
		MessageBox(NULL, "命名管道连接失败！", "[控制端]", MB_OK);
		return FALSE;
	}
}

BOOL ClientConnectPipe(const char* PipeName)
{
	if (WaitNamedPipe(PipeName, NMPWAIT_WAIT_FOREVER) == FALSE)
	{
		MessageBox(NULL, "命名管道连接失败", "[被注入端]", MB_OK);

		return FALSE;
	}
	else
	{
		return TRUE;
	}
}

VOID ClosePipe(HANDLE& hPipe)
{
	DisconnectNamedPipe(hPipe);
	CloseHandle(hPipe);
}

BOOL EnableDebugPrivilege()
{
	HANDLE hToken;
	BOOL fOk = FALSE;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);

		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

		fOk = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return fOk;
}