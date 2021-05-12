#include <Windows.h>
#include "resource.h"
#include "../PE Module/PeTools.h"
#include "../Proc Module/Process.h"
#include "../Api Module/ApiFunc.h"
using namespace std;

HWND g_hDlg = 0;						//主对话框句柄
DWORD g_dwRowId = 0;					//选中的函数
HINSTANCE g_hAppInstance;				//主窗口句柄
TCHAR* g_pModuleName = NULL;			//模块名
TCHAR g_szProcName[0x80] = { 0 };		//被选中进程名
DWORD g_dwChosedProcPid = 0;			//被选中进程PID
DWORD g_dwChosedProcAddr = 0;			//被选中进程基址
DWORD g_dwChosedProcSize = 0;			//被选中进程模块大小
TCHAR g_szChosedFunName[0x80] = { 0 };	//被选中函数名字
TCHAR g_szChosedFunState[0x80] = { 0 };	//被选中函数状态
TCHAR g_szChosedFunDLL[0x80] = { 0 };	//被选中函数所属DLL
HANDLE hPipe = NULL;					//命名管道
TCHAR g_szCustomAddr[256] = { 0 };		//自定义监控位置

//线程函数-等待客户端连接
DWORD WINAPI WaitClientConnect(
	LPVOID lpParameter   // thread data		
)
{
	WaitConnectPipe(hPipe);

	return 0;
}

//主界面回调函数
BOOL CALLBACK DialogMainProc(
	HWND hwndDlg,  // 窗口句柄			
	UINT uMsg,     // 消息			
	WPARAM wParam, // 消息参数1			
	LPARAM lParam  // 消息参数2			
)
{
	switch (uMsg)
	{
		case WM_INITDIALOG:
		{
			g_hDlg = hwndDlg;
			//初始化表头
			InitProcessListHeader(hwndDlg);
			InitFunctionListHeader(hwndDlg);
			//遍历进程
			EnumProcess(hwndDlg);

			return TRUE;
		}
		case WM_COMMAND:
		{
			switch (LOWORD(wParam))
			{
				case IDC_BUTTON_REFRESH:
				{
					//重新遍历进程
					EnumProcess(hwndDlg);
					return TRUE;
				}
				case IDC_BUTTON_CHOOSEFILE:
				{
					//选择文件
					g_pModuleName = GetFileName(hwndDlg);
					//填充编辑框
					SendDlgItemMessage(hwndDlg, IDC_EDIT_DLLPATH, WM_SETTEXT, 0, (DWORD)g_pModuleName);

					return TRUE;
				}
				case IDC_BUTTON_FUNCTIONOK:
				{
					//从编辑框中获取要HOOK的地址
					GetDlgItemText(hwndDlg, IDC_EDIT_IMPORTFUNCTION, g_szCustomAddr, 256);

					return TRUE;
				}
				case IDC_BUTTON_INJECT:
				{
					if (InjectModule(g_pModuleName))
					{
						MessageBox(hwndDlg,"模块注入成功！","成功",MB_OK);
					}
					else
					{
						MessageBox(hwndDlg, "模块注入失败！", "错误", MB_OK);
						return FALSE;
					}
					//创建线程，等待命名信道连接
					HANDLE hWaitThread = ::CreateThread(NULL, 0, WaitClientConnect, 0, 0, NULL);
					if (!hWaitThread)
					{
						MessageBox(hwndDlg, "创建线程失败！", "错误", MB_OK);
					}

					return TRUE;
				}
				case IDC_BUTTON_STARTMONITOR:
				{
					char szBtnText[20] = { 0 };
					GetDlgItemText(hwndDlg, IDC_BUTTON_STARTMONITOR, szBtnText, 20);
					if (strcmp(szBtnText, "停止监控") == 0)
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
					if (strcmp(szBtnText, "停止自定义监控") == 0)
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
			//单击进程列表
			if (wParam == IDC_LIST_PROCESS && pNMHDR->code == NM_CLICK)
			{
				//获取选中进程信息
				GetChosProcInfo(hwndDlg);
				//遍历函数列表
				EnumFunctions(hwndDlg);
			}
			//单击函数列表
			if (wParam == IDC_LIST_FUNCTION && pNMHDR->code == NM_CLICK)
			{
				HWND hListFunction;					//FunctionList句柄
				//获取句柄
				hListFunction = GetDlgItem(hwndDlg, IDC_LIST_FUNCTION);
				//获取选中行
				GetRow(hListFunction);

				TCHAR szTempBuffer[256] = { 0 };
				LV_ITEM vitem;								//List的数据项
				memset(&vitem, 0, sizeof(LV_ITEM));
				vitem.iSubItem = 2;							//要提取的列
				vitem.pszText = szTempBuffer;				//指定存储查询结果的缓冲区
				vitem.cchTextMax = 0x80;					//要提取的尺寸
				SendMessage(hListFunction, LVM_GETITEMTEXT, g_dwRowId, (DWORD)&vitem);

				if (strcmp(szTempBuffer, "监控中") == 0)
				{
					SetDlgItemText(hwndDlg, IDC_BUTTON_STARTMONITOR, "停止监控");
					//g_dwRowId = -1;
				}
				else
				{
					SetDlgItemText(hwndDlg, IDC_BUTTON_STARTMONITOR, "监控API");
				}
			}
			//双击进程列表
			if (wParam == IDC_LIST_PROCESS && pNMHDR->code == NM_DBLCLK)
			{
				//填充选中进程编辑框，获取进程基址
				FillChooseProcess(hwndDlg);
			}
			//双击函数列表
			if (wParam == IDC_LIST_FUNCTION && pNMHDR->code == NM_DBLCLK)
			{
				//获取选中函数信息
				GetChosFunInfo(hwndDlg);
				MessageBox(hwndDlg, g_szChosedFunName, "[选中函数]", MB_OK);
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

//主函数
int CALLBACK WinMain(
	_In_  HINSTANCE hInstance,
	_In_  HINSTANCE hPrevInstance,
	_In_  LPSTR lpCmdLine,
	_In_  int nCmdShow
)
{
	//创建命名管道
	CreatePipe(hPipe);

	//加载主界面Dialog
	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, DialogMainProc);

	//打印错误代码
	DWORD errorCode = GetLastError();

	//关闭命名管道
	ClosePipe(hPipe);
	return 0;
}