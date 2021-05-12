#include "Process.h"

extern TCHAR g_szChosedFunName[0x80];
extern TCHAR g_szChosedFunDLL[0x80];
extern HANDLE hPipe;
extern HWND g_hDlg;
extern DWORD g_dwRowId;
extern TCHAR g_szCustomAddr[256];

BOOL CreatePipe(HANDLE& hPipe)
{
	const char* g_pStrPipeName = "\\\\.\\pipe\\NamePipe_Fly";	//�ܵ�����
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
		MessageBox(NULL, "�����ܵ����ӳɹ�����ʼͨ�ţ�", "[���ƶ�]", MB_OK);
		return TRUE;
	}
	else
	{
		MessageBox(NULL, "�����ܵ�����ʧ�ܣ�", "[���ƶ�]", MB_OK);
		return FALSE;
	}
}

BOOL ClientConnectPipe(const char* PipeName)
{
	if (WaitNamedPipe(PipeName, NMPWAIT_WAIT_FOREVER) == FALSE)
	{
		MessageBox(NULL, "�����ܵ�����ʧ��", "[��ע���]", MB_OK);

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
			//����ͨ��-���ͼ��APIָ��
			strcat(szShell, "���API");
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
				LV_ITEM vitem;								//List��������
				memset(&vitem, 0, sizeof(LV_ITEM));
				HWND hListFunction = GetDlgItem(g_hDlg, IDC_LIST_FUNCTION);
				vitem.iSubItem = 2;							//Ҫ��ȡ����
				vitem.pszText = (char*)"�����";				//ָ���洢��ѯ����Ļ�����
				SendMessage(hListFunction, LVM_SETITEMTEXT, g_dwRowId, (DWORD)&vitem);
			}

			break;
		}
		case 1:
		{
			//����ֹͣ���ָ��
			strcat(szShell, "ֹͣ���API");
			strcat(szShell, "|");
			strcat(szShell, g_szChosedFunName);
			strcat(szShell, "|");
			WriteFile(hPipe, szShell, strlen(szShell) + 1, &dwLen, NULL);

			char szRes[2] = { 0 };
			ReadFile(hPipe, szRes, 1, &dwLen, NULL);

			if (szRes[0] == 'Y')
			{
				LV_ITEM vitem;								//List��������
				memset(&vitem, 0, sizeof(LV_ITEM));
				HWND hListFunction = GetDlgItem(g_hDlg, IDC_LIST_FUNCTION);
				vitem.iSubItem = 2;							//Ҫ��ȡ����
				vitem.pszText = (char*)"δ�����";			//ָ���洢��ѯ����Ļ�����
				SendMessage(hListFunction, LVM_SETITEMTEXT, g_dwRowId, (DWORD)&vitem);
			}

			break;
		}
		case 2:
		{
			//����Inline HOOKָ��
						//�����Զ�����|013C1B63/20716387
			char szShell[256] = { 0 };
			DWORD dwLen;
			strcat(szShell, "�Զ�����");
			strcat(szShell, "|");
			strcat(szShell, g_szCustomAddr);
			strcat(szShell, "|");
			WriteFile(hPipe, szShell, strlen(szShell) + 1, &dwLen, NULL);

			char szRes[2] = { 0 };
			ReadFile(hPipe, szRes, 1, &dwLen, NULL);
			if (szRes[0] == 'Y')
			{
				SetDlgItemText(g_hDlg, IDC_BUTTON_INLINEHOOKSTART, "ֹͣ�Զ�����");
			}

			break;
		}
		case 3:
		{
			//����ֹͣ���ָ��
			strcat(szShell, "ֹͣ�Զ�����");
			strcat(szShell, "|");
			WriteFile(hPipe, szShell, strlen(szShell) + 1, &dwLen, NULL);

			char szRes[2] = { 0 };
			ReadFile(hPipe, szRes, 1, &dwLen, NULL);

			if (szRes[0] == 'Y')
			{
				SetDlgItemText(g_hDlg, IDC_BUTTON_INLINEHOOKSTART, "����Զ����ַ");
			}

			break;
		}
		case 4:
		{
			//����Զ�̵���ָ��
			char szShell[256] = { 0 };
			DWORD dwLen;
			strcat(szShell, "Զ�̵���");
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