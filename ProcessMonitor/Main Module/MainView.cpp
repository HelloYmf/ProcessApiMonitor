#include <Windows.h>
#include "resource.h"
#include "../PE Module/PeTools.h"
#include "../Proc Module/Process.h"
#include "../Api Module/ApiFunc.h"
using namespace std;

HWND g_hDlg = 0;						//���Ի�����
DWORD g_dwRowId = 0;					//ѡ�еĺ���
HINSTANCE g_hAppInstance;				//�����ھ��
TCHAR* g_pModuleName = NULL;			//ģ����
TCHAR g_szProcName[0x80] = { 0 };		//��ѡ�н�����
DWORD g_dwChosedProcPid = 0;			//��ѡ�н���PID
DWORD g_dwChosedProcAddr = 0;			//��ѡ�н��̻�ַ
DWORD g_dwChosedProcSize = 0;			//��ѡ�н���ģ���С
TCHAR g_szChosedFunName[0x80] = { 0 };	//��ѡ�к�������
TCHAR g_szChosedFunState[0x80] = { 0 };	//��ѡ�к���״̬
TCHAR g_szChosedFunDLL[0x80] = { 0 };	//��ѡ�к�������DLL
HANDLE hPipe = NULL;					//�����ܵ�
TCHAR g_szCustomAddr[256] = { 0 };		//�Զ�����λ��

//�̺߳���-�ȴ��ͻ�������
DWORD WINAPI WaitClientConnect(
	LPVOID lpParameter   // thread data		
)
{
	WaitConnectPipe(hPipe);

	return 0;
}

//������ص�����
BOOL CALLBACK DialogMainProc(
	HWND hwndDlg,  // ���ھ��			
	UINT uMsg,     // ��Ϣ			
	WPARAM wParam, // ��Ϣ����1			
	LPARAM lParam  // ��Ϣ����2			
)
{
	switch (uMsg)
	{
		case WM_INITDIALOG:
		{
			g_hDlg = hwndDlg;
			//��ʼ����ͷ
			InitProcessListHeader(hwndDlg);
			InitFunctionListHeader(hwndDlg);
			//��������
			EnumProcess(hwndDlg);

			return TRUE;
		}
		case WM_COMMAND:
		{
			switch (LOWORD(wParam))
			{
				case IDC_BUTTON_REFRESH:
				{
					//���±�������
					EnumProcess(hwndDlg);
					return TRUE;
				}
				case IDC_BUTTON_CHOOSEFILE:
				{
					//ѡ���ļ�
					g_pModuleName = GetFileName(hwndDlg);
					//���༭��
					SendDlgItemMessage(hwndDlg, IDC_EDIT_DLLPATH, WM_SETTEXT, 0, (DWORD)g_pModuleName);

					return TRUE;
				}
				case IDC_BUTTON_FUNCTIONOK:
				{
					//�ӱ༭���л�ȡҪHOOK�ĵ�ַ
					GetDlgItemText(hwndDlg, IDC_EDIT_IMPORTFUNCTION, g_szCustomAddr, 256);

					return TRUE;
				}
				case IDC_BUTTON_INJECT:
				{
					if (InjectModule(g_pModuleName))
					{
						MessageBox(hwndDlg,"ģ��ע��ɹ���","�ɹ�",MB_OK);
					}
					else
					{
						MessageBox(hwndDlg, "ģ��ע��ʧ�ܣ�", "����", MB_OK);
						return FALSE;
					}
					//�����̣߳��ȴ������ŵ�����
					HANDLE hWaitThread = ::CreateThread(NULL, 0, WaitClientConnect, 0, 0, NULL);
					if (!hWaitThread)
					{
						MessageBox(hwndDlg, "�����߳�ʧ�ܣ�", "����", MB_OK);
					}

					return TRUE;
				}
				case IDC_BUTTON_STARTMONITOR:
				{
					char szBtnText[20] = { 0 };
					GetDlgItemText(hwndDlg, IDC_BUTTON_STARTMONITOR, szBtnText, 20);
					if (strcmp(szBtnText, "ֹͣ���") == 0)
					{
						SendShell(1);
					}
					else 
					{
						SendShell(0);
					}
					return TRUE;
				}
				case IDC_BUTTON_REMOTECALL:
				{
					SendShell(4);

					return TRUE;
				}
				case IDC_BUTTON_INLINEHOOKSTART:
				{
					TCHAR szBtnText[20] = { 0 };
					GetDlgItemText(hwndDlg, IDC_BUTTON_INLINEHOOKSTART, szBtnText, 20);
					if (strcmp(szBtnText, "ֹͣ�Զ�����") == 0)
					{
						SendShell(3);
					}
					else
					{
						SendShell(2);
					}
				}
			}
			return FALSE;
		}
		case WM_NOTIFY:
		{
			NMHDR* pNMHDR = (NMHDR*)lParam;
			//���������б�
			if (wParam == IDC_LIST_PROCESS && pNMHDR->code == NM_CLICK)
			{
				//��ȡѡ�н�����Ϣ
				GetChosProcInfo(hwndDlg);
				//���������б�
				EnumFunctions(hwndDlg);
			}
			//���������б�
			if (wParam == IDC_LIST_FUNCTION && pNMHDR->code == NM_CLICK)
			{
				HWND hListFunction;					//FunctionList���
				//��ȡ���
				hListFunction = GetDlgItem(hwndDlg, IDC_LIST_FUNCTION);
				//��ȡѡ����
				GetRow(hListFunction);

				TCHAR szTempBuffer[256] = { 0 };
				LV_ITEM vitem;								//List��������
				memset(&vitem, 0, sizeof(LV_ITEM));
				vitem.iSubItem = 2;							//Ҫ��ȡ����
				vitem.pszText = szTempBuffer;				//ָ���洢��ѯ����Ļ�����
				vitem.cchTextMax = 0x80;					//Ҫ��ȡ�ĳߴ�
				SendMessage(hListFunction, LVM_GETITEMTEXT, g_dwRowId, (DWORD)&vitem);

				if (strcmp(szTempBuffer, "�����") == 0)
				{
					SetDlgItemText(hwndDlg, IDC_BUTTON_STARTMONITOR, "ֹͣ���");
					//g_dwRowId = -1;
				}
				else
				{
					SetDlgItemText(hwndDlg, IDC_BUTTON_STARTMONITOR, "���API");
				}
			}
			//˫�������б�
			if (wParam == IDC_LIST_PROCESS && pNMHDR->code == NM_DBLCLK)
			{
				//���ѡ�н��̱༭�򣬻�ȡ���̻�ַ
				FillChooseProcess(hwndDlg);
			}
			//˫�������б�
			if (wParam == IDC_LIST_FUNCTION && pNMHDR->code == NM_DBLCLK)
			{
				//��ȡѡ�к�����Ϣ
				GetChosFunInfo(hwndDlg);
				MessageBox(hwndDlg, g_szChosedFunName, "[ѡ�к���]", MB_OK);
			}
			return TRUE;
		}
		case WM_CLOSE:
		{
			EndDialog(hwndDlg, 0);
			return TRUE;
		}
	}
	return FALSE;
}

//������
int CALLBACK WinMain(
	_In_  HINSTANCE hInstance,
	_In_  HINSTANCE hPrevInstance,
	_In_  LPSTR lpCmdLine,
	_In_  int nCmdShow
)
{
	//���������ܵ�
	CreatePipe(hPipe);

	//����������Dialog
	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, DialogMainProc);

	//��ӡ�������
	DWORD errorCode = GetLastError();

	//�ر������ܵ�
	ClosePipe(hPipe);
	return 0;
}