// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include <Windows.h>
#include <stdio.h>
#include "../InjectDLL/Proc Module/Process_DLL.h"
#include "../InjectDLL/HOOK Module/HookFunctions_DLL.h"

typedef int(WINAPI* PFNMESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);

const char* g_pStrPipeName = "\\\\.\\pipe\\NamePipe_Fly";		//管道名称

//extern DWORD g_dwRetAddr;      //HOOK返回地址

DWORD g_dwOldFunAddr_MessBox;		//HOOK前的MessageBox地址
DWORD g_dwOldFunAddr_CreaFile;		//HOOK前的CreateFile地址

//修复IAT表指向的地址
BOOL FixCurrentIAT(DWORD ImageBuffer)
{
	PBYTE pImageTemp = (PBYTE)ImageBuffer;
	PIMAGE_DOS_HEADER DosHeader_Image = (PIMAGE_DOS_HEADER)pImageTemp;					//获取DOS头
	pImageTemp = pImageTemp + ((PIMAGE_DOS_HEADER)pImageTemp)->e_lfanew;				//偏移到NT头
	PIMAGE_NT_HEADERS NtHeader_Image = (PIMAGE_NT_HEADERS)pImageTemp;					//获取NT头
	pImageTemp = pImageTemp + 0x4;														//偏移到标准PE头
	PIMAGE_FILE_HEADER FileHeader_Image = (PIMAGE_FILE_HEADER)pImageTemp;				//获取标准PE头
	pImageTemp = pImageTemp + 0x14;														//偏移到可选PE头
	PIMAGE_OPTIONAL_HEADER OptionalHeader_Image = (PIMAGE_OPTIONAL_HEADER)pImageTemp;	//获取可选PE头

	PIMAGE_IMPORT_DESCRIPTOR pImportDesriptor = (PIMAGE_IMPORT_DESCRIPTOR)(OptionalHeader_Image->DataDirectory[1].VirtualAddress
		+ (DWORD)ImageBuffer);															//获取导入表指针
	if (!pImportDesriptor->OriginalFirstThunk && !pImportDesriptor)
	{
		MessageBox(0, "没有INT表", "错误", MB_OK);
		return FALSE;
	}
	//临时指针
	PIMAGE_IMPORT_DESCRIPTOR pTemp = pImportDesriptor;
	//标记所有导入表结束
	int flag = 1;

	//外层循环，遍历全部导入表
	while (flag)
	{
		flag = 0;
		if (pTemp->Name == NULL)
		{
			break;
		}
		//判断导入表结束
		for (int j = 0; j < sizeof(IMAGE_IMPORT_DESCRIPTOR); j++)
		{
			if (((PBYTE)pTemp)[j] != 0)
			{
				flag = 1;
				break;
			}
		}
		HMODULE hDLL = LoadLibrary((LPCSTR)(pTemp->Name + (DWORD)ImageBuffer));
		for (int k = 0;; k++)
		{
			if (((PDWORD)(pTemp->OriginalFirstThunk + (DWORD)ImageBuffer))[k] != 0)
			{
				if (((PDWORD)(pTemp->OriginalFirstThunk + (DWORD)ImageBuffer))[k] >> 0x1F == 1)
				{
					PIMAGE_THUNK_DATA pTempOri = &((PIMAGE_THUNK_DATA)(pTemp->FirstThunk + (DWORD)ImageBuffer))[k];
					pTempOri->u1.Function = (DWORD)GetProcAddress(hDLL,
						(LPCSTR)(((PDWORD)(pTemp->OriginalFirstThunk + (DWORD)ImageBuffer))[k] & 0x7FFFFFFF));
				}
				else
				{
					PIMAGE_THUNK_DATA pTempOri = &((PIMAGE_THUNK_DATA)(pTemp->FirstThunk + (DWORD)ImageBuffer))[k];
					pTempOri->u1.Function = (DWORD)GetProcAddress(hDLL,
						((PIMAGE_IMPORT_BY_NAME)(((PDWORD)(pTemp->OriginalFirstThunk + (DWORD)ImageBuffer))[k] + (DWORD)ImageBuffer))->Name);
				}
			}
			else
			{
				break;
			}
		}
		pTemp++;
	}
	return TRUE;
}
//初始化-进程通信-命名管道
BOOL InitProcCommunication(HANDLE& hPipe)
{
	Sleep(2000);
	//连接命名管道
	if (!ClientConnectPipe(g_pStrPipeName))
	{
		return FALSE;
	}
	//打开命名管道
	OpenPipe(hPipe, g_pStrPipeName);

	return TRUE;
}

//远程线程注入调用函数
extern "C" __declspec(dllexport) DWORD WINAPI InjectEntry(
	LPVOID ImageBuffer   // thread data		
)
{
	//修复IAT的地址
	FixCurrentIAT((DWORD)ImageBuffer);

	//获取自身进程信息
	TCHAR szModule[MAX_PATH] = { 0 };
	GetModuleFileName(NULL, szModule, MAX_PATH);

	//进程通信-命名管道
	HANDLE hPipe = NULL;
	InitProcCommunication(hPipe);

	//获取旧函数地址
	g_dwOldFunAddr_MessBox = (DWORD)GetProcAddress(LoadLibrary("User32.dll"), "MessageBoxA");
	g_dwOldFunAddr_CreaFile = (DWORD)GetProcAddress(LoadLibrary("Kernel32.dll"), "CreateFileA");

	while (1)
	{
		//接收控制端发回的数据
		char szShell[256] = { 0 };	//接收通信数据
		DWORD dwLen = 0;			//实际写入字节数
		//读取管道中的内容（管道是一种特殊的文件）
		ReadFile(hPipe, szShell, 256, &dwLen, NULL);

		TCHAR szShellType[256] = { 0 };		//指令类型
		TCHAR szInlineHookAddr[256] = { 0 };//Inline HOOK地址
		TCHAR szFunName[256] = { 0 };		//函数名字
		TCHAR szFunDLL[256] = { 0 };		//所属DLL

		if (dwLen)
		{
			TCHAR* pTemp = szShell;
			int i = 0;
			while (*pTemp != '|')
			{
				szShellType[i] = *pTemp;
				i++;
				pTemp++;
			}
			if (strcmp(szShellType, "远程调用") == 0)
			{
				pTemp++;
				i = 0;
				while (*pTemp != '|')
				{
					szFunName[i] = *pTemp;
					i++;
					pTemp++;
				}
				if (strcmp(szFunName, "MessageBoxA") == 0)
				{
					DWORD pFunAddr = (DWORD)GetProcAddress(LoadLibrary("User32.dll"), "MessageBoxA");
					PFNMESSAGEBOXA RemoteFunction = (PFNMESSAGEBOXA)pFunAddr;
					RemoteFunction(0, "远程调用了MessageBoxA", "[成功]", 0);
				}
			}
			else if (strcmp(szShellType, "停止监控API") == 0)
			{
				pTemp++;
				i = 0;
				while (*pTemp != '|')
				{
					szFunName[i] = *pTemp;
					i++;
					pTemp++;
				}
				if (strcmp(szFunName, "MessageBoxA") == 0)
				{
					if (UnSetIATHook((DWORD)g_dwOldFunAddr_MessBox, (DWORD)myMessageBoxA))
					{
						((PFNMESSAGEBOXA)g_dwOldFunAddr_MessBox)(NULL, "停止IAT HOOK MessageBoxA成功！", "[成功]", MB_OK);
						WriteFile(hPipe, "Y", strlen("Y"), &dwLen, NULL);
					}
					else
					{
						((PFNMESSAGEBOXA)g_dwOldFunAddr_MessBox)(NULL, "停止IAT HOOK MessageBoxA失败！", "[失败]", MB_OK);
						WriteFile(hPipe, "N", strlen("N"), &dwLen, NULL);
					}
				}
				else if (strcmp(szFunName, "CreateFileA") == 0)
				{
					if (UnSetIATHook((DWORD)g_dwOldFunAddr_CreaFile, (DWORD)myCreateFileA))
					{
						MessageBox(NULL, "停止IAT HOOK CreateFileA成功！", "[成功]", MB_OK);
						WriteFile(hPipe, "Y", strlen("Y"), &dwLen, NULL);
					}
					else
					{
						MessageBox(NULL, "停止IAT HOOK CreateFileA失败！", "[失败]", MB_OK);
						WriteFile(hPipe, "N", strlen("N"), &dwLen, NULL);
					}
				}
			}
			else if(strcmp(szShellType, "监控API") == 0)
			{
				pTemp++;
				i = 0;
				while (*pTemp != '|')
				{
					szFunName[i] = *pTemp;
					i++;
					pTemp++;
				}
				pTemp++;
				i = 0;
				while (*pTemp != '|')
				{
					szFunDLL[i] = *pTemp;
					i++;
					pTemp++;
				}
				if (strcmp(szFunName, "MessageBoxA") == 0)
				{
					if (SetIATHook((DWORD)g_dwOldFunAddr_MessBox, (DWORD)myMessageBoxA))
					{
						((PFNMESSAGEBOXA)g_dwOldFunAddr_MessBox)(NULL, "IAT HOOK MessageBoxA成功！", "[成功]", MB_OK);
						WriteFile(hPipe, "Y", strlen("Y"), &dwLen, NULL);
					}
					else
					{
						((PFNMESSAGEBOXA)g_dwOldFunAddr_MessBox)(NULL, "IAT HOOK MessageBoxA失败！", "[失败]", MB_OK);
						WriteFile(hPipe, "N", strlen("N"), &dwLen, NULL);
					}
				}
				else if (strcmp(szFunName, "CreateFileA") == 0)
				{
					if (SetIATHook((DWORD)g_dwOldFunAddr_CreaFile, (DWORD)myCreateFileA))
					{
						MessageBox(NULL, "IAT HOOK CreateFileA成功！", "[成功]", MB_OK);
						WriteFile(hPipe, "Y", strlen("Y"), &dwLen, NULL);
					}
					else
					{
						MessageBox(NULL, "IAT HOOK CreateFileA失败！", "[失败]", MB_OK);
						WriteFile(hPipe, "N", strlen("N"), &dwLen, NULL);
					}
				}
			}
			else if (strcmp(szShellType, "自定义监控") == 0)
			{
				//接收Inline HOOK地址
				pTemp++;
				i = 0;
				while (*pTemp != '|')
				{
					szInlineHookAddr[i] = *pTemp;
					i++;
					pTemp++;
				}
				DWORD dwInlineHookAddr = 0;
				sscanf(szInlineHookAddr, "%d", &dwInlineHookAddr);
				//设置Inline HOOK
				if (SetInlineHOOK(dwInlineHookAddr, 6))
				{
					MessageBox(NULL,"自定义监控成功", "[成功]", MB_OK);
					WriteFile(hPipe, "Y", strlen("Y"), &dwLen, NULL);
				}
				else
				{
					MessageBox(NULL, "自定义监控失败", "[失败]", MB_OK);
					WriteFile(hPipe, "N", strlen("N"), &dwLen, NULL);
				}
			}
			else if (strcmp(szShellType, "停止自定义监控") == 0)
			{
				if (UnSetInlineHOOK())
				{
					MessageBox(NULL, "停止自定义监控成功", "[成功]", MB_OK);
					WriteFile(hPipe, "Y", strlen("Y"), &dwLen, NULL);
				}
				else
				{
					MessageBox(NULL, "停止自定义监控失败", "[失败]", MB_OK);
					WriteFile(hPipe, "N", strlen("N"), &dwLen, NULL);
				}
			}
		}
	}

	CloseHandle(hPipe);
	return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
