#include "HookFunctions_DLL.h"

typedef struct _REGISTER
{
	DWORD Eax;
	DWORD Ecx;
	DWORD Edx;
	DWORD Ebx;
	DWORD Esp;
	DWORD Ebp;
	DWORD Esi;
	DWORD Edi;
}Register;

Register g_reg = { 0 };
DWORD g_dwParamX = 0;
DWORD g_dwParamY = 0;
char g_szBuffer[256] = { 0 };

//全局变量
DWORD g_dwHookAddr;     //HOOK开始地址
DWORD g_dwRetAddr;      //HOOK返回地址
DWORD g_dwHookLen;      //HOOK硬编码长度
PBYTE g_pCodePatch;     //存储HOOK之前的硬编码
DWORD g_dwOldProtect;   //原内存页属性
BOOL g_bHookFlag;       //HOOK是否成功，True:成功，False:失败

extern DWORD g_dwOldFunAddr_MessBox;		//HOOK前的MessageBox地址
extern DWORD g_dwOldFunAddr_CreaFile;		//HOOK前的CreateFile地址

typedef int(WINAPI* PFNMESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);
typedef HANDLE(WINAPI* PFNCREATEFILEA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

extern "C" _declspec(naked) VOID HookProc()
{

	//保存寄存器和标志寄存器信息
	_asm
	{
		pushad
		pushfd
	}
	//执行自己代码
	_asm
	{
		mov g_reg.Eax, eax
		mov g_reg.Ecx, ecx
		mov g_reg.Edx, edx
		mov g_reg.Ebx, ebx
		mov g_reg.Esp, esp
		mov g_reg.Ebp, ebp
		mov g_reg.Edi, edi
		mov g_reg.Esi, esi

		mov eax, DWORD PTR SS : [esp + 0x2c]
		mov g_dwParamX, eax
		mov ecx, DWORD PTR SS : [esp + 0x30]
		mov g_dwParamY, ecx
	}
	sprintf_s(g_szBuffer, " Eax:%x\n Ecx:%x\n Edx:%x\n Ebx:%x\n Esp:%x\n Ebp:%x\n Edi:%x\n Esi:%x\n\n ParamX:%x\n ParamY:%x\n ",
		g_reg.Eax, g_reg.Ecx, g_reg.Edx, g_reg.Ebx, g_reg.Esp, g_reg.Ebp, g_reg.Edi, g_reg.Esi, g_dwParamX, g_dwParamY);
	MessageBox(0, g_szBuffer, "[Inline HOOK Info]", MB_OK);
	//恢复寄存器
	_asm
	{
		popfd
		popad
	}
	//执行被覆盖的指令
	_asm
	{
		sub esp, 0C0h
	}
	//跳回HOOK位置
	_asm
	{
		jmp g_dwRetAddr
	}
}

int WINAPI myMessageBoxA(
	HWND   hWnd,
	LPCSTR lpText,
	LPCSTR lpCaption,
	UINT   uType
)
{
	//获取参数存文件
	

	BOOL ret = ((PFNMESSAGEBOXA)g_dwOldFunAddr_MessBox)(hWnd, lpText, lpCaption, uType);

	//获取返回值存文件

	return ret;
}

HANDLE WINAPI myCreateFileA(
	LPCSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
)
{
	HANDLE hHookLog = CreateFileA("E:/HookInfo.txt", GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
	DWORD dwSize = GetFileSize(hHookLog, NULL);
	SetFilePointer(hHookLog, 0, NULL, FILE_END);

	char szBuffer[256] = { 0 };
	char szRet[256] = { 0 };
	size_t CopySize = 0;

	//获取参数存文件
	strcat(szBuffer, "调用CerateFileA：\n");
	CopySize += strlen("调用CerateFileA：\n");
	strcat(szBuffer, "打开的文件路径：");
	CopySize += strlen("打开的文件路径：");
	strcat(szBuffer, lpFileName);
	CopySize += strlen(lpFileName);
	strcat(szBuffer, "\n");
	CopySize += strlen("\n");

	//获取返回值存文件
	HANDLE ret = ((PFNCREATEFILEA)g_dwOldFunAddr_CreaFile)(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	strcat(szBuffer, "函数返回值：");
	CopySize += strlen("函数返回值：");
	sprintf(szRet, "%0X", (DWORD)ret);
	strcat(szBuffer, szRet);
	CopySize += strlen(szRet);
	strcat(szBuffer, "\n");
	CopySize += strlen("\n");

	//写入文件
	WriteFile(hHookLog, szBuffer, CopySize, NULL, 0);

	CloseHandle(hHookLog);
	return ret;
}


//设置IAT HOOK
BOOL SetIATHook(DWORD oldFunAddr, DWORD newFunAddr)
{
	DWORD dwImageBase = (DWORD)GetModuleHandle(NULL);
	//遍历IAT表
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dwImageBase;												//获取DOS头
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(dwImageBase + pDosHeader->e_lfanew);						//获取NT头
	PIMAGE_IMPORT_DESCRIPTOR pImportDesriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pNtHeader->OptionalHeader.DataDirectory[1].VirtualAddress
		+ dwImageBase);															//获取导入表指针
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
		PDWORD pThunkData = (PDWORD)(pTemp->FirstThunk + dwImageBase);
		while (*pThunkData)
		{
			if (*pThunkData == oldFunAddr)
			{
				DWORD r = 0;
				VirtualProtect(pThunkData, 4, PAGE_EXECUTE_WRITECOPY, &r);
				*pThunkData = newFunAddr;
				return TRUE;
			}
			pThunkData++;
		}
		pTemp++;
	}
	return FALSE;
}

//卸载IAT HOOK
BOOL UnSetIATHook(DWORD oldFunAddr, DWORD newFunAddr)
{
	DWORD dwImageBase = (DWORD)GetModuleHandle(NULL);
	//遍历IAT表
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dwImageBase;												//获取DOS头
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(dwImageBase + pDosHeader->e_lfanew);						//获取NT头
	PIMAGE_IMPORT_DESCRIPTOR pImportDesriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pNtHeader->OptionalHeader.DataDirectory[1].VirtualAddress
		+ dwImageBase);															//获取导入表指针
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
		PDWORD pThunkData = (PDWORD)(pTemp->FirstThunk + dwImageBase);
		while (*pThunkData)
		{
			if (*pThunkData == newFunAddr)
			{
				DWORD r = 0;
				VirtualProtect(pThunkData, 4, PAGE_EXECUTE_WRITECOPY, &r);
				*pThunkData = oldFunAddr;
				return TRUE;
			}
			pThunkData++;
		}
		pTemp++;
	}
	return FALSE;
}

//设置Inline HOOK
BOOL SetInlineHOOK(DWORD dwHookAddr, DWORD dwHookLen)
{
	//局部变量
	DWORD dwJmpCode = 0;
	//参数校验
	if (!dwHookAddr || !(DWORD)HookProc)
	{
		MessageBox(NULL,"传递参数有误！","错误",MB_OK);
		return g_bHookFlag;
	}
	//判断长度
	if (dwHookLen < 5)
	{
		MessageBox(NULL, "长度不足5个字节！", "错误", MB_OK);
		return g_bHookFlag;
	}
	//修改HOOK内存块属性
	VirtualProtect((LPVOID)dwHookAddr, dwHookLen, PAGE_EXECUTE_WRITECOPY, &g_dwOldProtect);
	//申请内存，保存原来的硬编码
	g_pCodePatch = (PBYTE)malloc(sizeof(BYTE) * dwHookLen);
	memcpy(g_pCodePatch, (LPVOID)dwHookAddr, dwHookLen);
	//获取要跳转的地址
	dwJmpCode = (DWORD)HookProc - dwHookAddr - 0x5;
	//初始化HOOK位置内存(NOP->0x90)
	memset((PVOID)dwHookAddr, 0x90, dwHookLen);
	//修改HOOK位置硬编码
	*((PBYTE)dwHookAddr) = 0xE9;
	*((PDWORD)(dwHookAddr + 0x1)) = dwJmpCode;
	//修改全局变量
	g_dwHookAddr = dwHookAddr;
	g_dwRetAddr = dwHookAddr + dwHookLen;
	g_dwHookLen = dwHookLen;
	g_bHookFlag = TRUE;
	//返回
	return g_bHookFlag;


	return TRUE;
}

//卸载Inline HOOK
BOOL UnSetInlineHOOK()
{
	//判断是否HOOK成功
	if (!g_bHookFlag)
	{
		MessageBox(NULL,"当前没有HOOK！","[提示]",MB_OK);
		return FALSE;
	}
	//写入原来的硬编码
	memcpy((LPVOID)g_dwHookAddr, g_pCodePatch, g_dwHookLen);
	//恢复内存页属性
	VirtualProtect((LPVOID)g_dwHookAddr, g_dwHookLen, g_dwOldProtect, NULL);
	//修改全局变量
	g_bHookFlag = FALSE;
	free(g_pCodePatch);
	g_pCodePatch = NULL;
	g_dwHookLen = 0;
	g_dwHookAddr = 0;
	g_dwRetAddr = 0;
	//返回
	return TRUE;
}