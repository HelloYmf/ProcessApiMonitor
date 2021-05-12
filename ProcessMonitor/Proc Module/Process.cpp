#include "Process.h"

extern TCHAR g_szChosedFunName[0x80];
extern TCHAR g_szChosedFunDLL[0x80];
extern HANDLE hPipe;
extern HWND g_hDlg;
extern DWORD g_dwRowId;
extern TCHAR g_szCustomAddr[256];

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

VOID SendShell(DWORD ShellType)
{
	char szShell[256] = { 0 };
	DWORD dwLen;
	switch (ShellType)
	{
		case 0:
		{
			//进程通信-发送监控API指令
			strcat(szShell, "监控API");
			strcat(szShell, "|");
			strcat(szShell, g_szChosedFunName);
			strcat(szShell, "|");
			strcat(szShell, g_szChosedFunDLL);
			strcat(szShell, "|");
			WriteFile(hPipe, szShell, strlen(szShell) + 1, &dwLen, NULL);

			char szRes[2] = { 0 };
			ReadFile(hPipe, szRes, 1, &dwLen, NULL);

			if (szRes[0] == 'Y')
			{
				LV_ITEM vitem;								//List的数据项
				memset(&vitem, 0, sizeof(LV_ITEM));
				HWND hListFunction = GetDlgItem(g_hDlg, IDC_LIST_FUNCTION);
				vitem.iSubItem = 2;							//要提取的列
				vitem.pszText = (char*)"监控中";				//指定存储查询结果的缓冲区
				SendMessage(hListFunction, LVM_SETITEMTEXT, g_dwRowId, (DWORD)&vitem);
			}

			break;
		}
		case 1:
		{
			//发送停止监控指令
			strcat(szShell, "停止监控API");
			strcat(szShell, "|");
			strcat(szShell, g_szChosedFunName);
			strcat(szShell, "|");
			WriteFile(hPipe, szShell, strlen(szShell) + 1, &dwLen, NULL);

			char szRes[2] = { 0 };
			ReadFile(hPipe, szRes, 1, &dwLen, NULL);

			if (szRes[0] == 'Y')
			{
				LV_ITEM vitem;								//List的数据项
				memset(&vitem, 0, sizeof(LV_ITEM));
				HWND hListFunction = GetDlgItem(g_hDlg, IDC_LIST_FUNCTION);
				vitem.iSubItem = 2;							//要提取的列
				vitem.pszText = (char*)"未被监控";			//指定存储查询结果的缓冲区
				SendMessage(hListFunction, LVM_SETITEMTEXT, g_dwRowId, (DWORD)&vitem);
			}

			break;
		}
		case 2:
		{
			//发送Inline HOOK指令
						//例：自定义监控|013C1B63/20716387
			char szShell[256] = { 0 };
			DWORD dwLen;
			strcat(szShell, "自定义监控");
			strcat(szShell, "|");
			strcat(szShell, g_szCustomAddr);
			strcat(szShell, "|");
			WriteFile(hPipe, szShell, strlen(szShell) + 1, &dwLen, NULL);

			char szRes[2] = { 0 };
			ReadFile(hPipe, szRes, 1, &dwLen, NULL);
			if (szRes[0] == 'Y')
			{
				SetDlgItemText(g_hDlg, IDC_BUTTON_INLINEHOOKSTART, "停止自定义监控");
			}

			break;
		}
		case 3:
		{
			//发送停止监控指令
			strcat(szShell, "停止自定义监控");
			strcat(szShell, "|");
			WriteFile(hPipe, szShell, strlen(szShell) + 1, &dwLen, NULL);

			char szRes[2] = { 0 };
			ReadFile(hPipe, szRes, 1, &dwLen, NULL);

			if (szRes[0] == 'Y')
			{
				SetDlgItemText(g_hDlg, IDC_BUTTON_INLINEHOOKSTART, "监控自定义地址");
			}

			break;
		}
		case 4:
		{
			//发送远程调用指令
			char szShell[256] = { 0 };
			DWORD dwLen;
			strcat(szShell, "远程调用");
			strcat(szShell, "|");
			strcat(szShell, g_szChosedFunName);
			strcat(szShell, "|");
			WriteFile(hPipe, szShell, strlen(szShell) + 1, &dwLen, NULL);

			break;
		}
	}
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