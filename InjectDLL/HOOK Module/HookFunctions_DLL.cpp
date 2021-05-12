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

//ȫ�ֱ���
DWORD g_dwHookAddr;     //HOOK��ʼ��ַ
DWORD g_dwRetAddr;      //HOOK���ص�ַ
DWORD g_dwHookLen;      //HOOKӲ���볤��
PBYTE g_pCodePatch;     //�洢HOOK֮ǰ��Ӳ����
DWORD g_dwOldProtect;   //ԭ�ڴ�ҳ����
BOOL g_bHookFlag;       //HOOK�Ƿ�ɹ���True:�ɹ���False:ʧ��

extern DWORD g_dwOldFunAddr_MessBox;		//HOOKǰ��MessageBox��ַ
extern DWORD g_dwOldFunAddr_CreaFile;		//HOOKǰ��CreateFile��ַ

typedef int(WINAPI* PFNMESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);
typedef HANDLE(WINAPI* PFNCREATEFILEA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

extern "C" _declspec(naked) VOID HookProc()
{

	//����Ĵ����ͱ�־�Ĵ�����Ϣ
	_asm
	{
		pushad
		pushfd
	}
	//ִ���Լ�����
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
	//�ָ��Ĵ���
	_asm
	{
		popfd
		popad
	}
	//ִ�б����ǵ�ָ��
	_asm
	{
		sub esp, 0C0h
	}
	//����HOOKλ��
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
	//��ȡ�������ļ�
	

	BOOL ret = ((PFNMESSAGEBOXA)g_dwOldFunAddr_MessBox)(hWnd, lpText, lpCaption, uType);

	//��ȡ����ֵ���ļ�

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

	//��ȡ�������ļ�
	strcat(szBuffer, "����CerateFileA��\n");
	CopySize += strlen("����CerateFileA��\n");
	strcat(szBuffer, "�򿪵��ļ�·����");
	CopySize += strlen("�򿪵��ļ�·����");
	strcat(szBuffer, lpFileName);
	CopySize += strlen(lpFileName);
	strcat(szBuffer, "\n");
	CopySize += strlen("\n");

	//��ȡ����ֵ���ļ�
	HANDLE ret = ((PFNCREATEFILEA)g_dwOldFunAddr_CreaFile)(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	strcat(szBuffer, "��������ֵ��");
	CopySize += strlen("��������ֵ��");
	sprintf(szRet, "%0X", (DWORD)ret);
	strcat(szBuffer, szRet);
	CopySize += strlen(szRet);
	strcat(szBuffer, "\n");
	CopySize += strlen("\n");

	//д���ļ�
	WriteFile(hHookLog, szBuffer, CopySize, NULL, 0);

	CloseHandle(hHookLog);
	return ret;
}


//����IAT HOOK
BOOL SetIATHook(DWORD oldFunAddr, DWORD newFunAddr)
{
	DWORD dwImageBase = (DWORD)GetModuleHandle(NULL);
	//����IAT��
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dwImageBase;												//��ȡDOSͷ
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(dwImageBase + pDosHeader->e_lfanew);						//��ȡNTͷ
	PIMAGE_IMPORT_DESCRIPTOR pImportDesriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pNtHeader->OptionalHeader.DataDirectory[1].VirtualAddress
		+ dwImageBase);															//��ȡ�����ָ��
	//��ʱָ��
	PIMAGE_IMPORT_DESCRIPTOR pTemp = pImportDesriptor;
	//������е�������
	int flag = 1;
	//���ѭ��������ȫ�������
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

//ж��IAT HOOK
BOOL UnSetIATHook(DWORD oldFunAddr, DWORD newFunAddr)
{
	DWORD dwImageBase = (DWORD)GetModuleHandle(NULL);
	//����IAT��
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dwImageBase;												//��ȡDOSͷ
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(dwImageBase + pDosHeader->e_lfanew);						//��ȡNTͷ
	PIMAGE_IMPORT_DESCRIPTOR pImportDesriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pNtHeader->OptionalHeader.DataDirectory[1].VirtualAddress
		+ dwImageBase);															//��ȡ�����ָ��
	//��ʱָ��
	PIMAGE_IMPORT_DESCRIPTOR pTemp = pImportDesriptor;
	//������е�������
	int flag = 1;
	//���ѭ��������ȫ�������
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

//����Inline HOOK
BOOL SetInlineHOOK(DWORD dwHookAddr, DWORD dwHookLen)
{
	//�ֲ�����
	DWORD dwJmpCode = 0;
	//����У��
	if (!dwHookAddr || !(DWORD)HookProc)
	{
		MessageBox(NULL,"���ݲ�������","����",MB_OK);
		return g_bHookFlag;
	}
	//�жϳ���
	if (dwHookLen < 5)
	{
		MessageBox(NULL, "���Ȳ���5���ֽڣ�", "����", MB_OK);
		return g_bHookFlag;
	}
	//�޸�HOOK�ڴ������
	VirtualProtect((LPVOID)dwHookAddr, dwHookLen, PAGE_EXECUTE_WRITECOPY, &g_dwOldProtect);
	//�����ڴ棬����ԭ����Ӳ����
	g_pCodePatch = (PBYTE)malloc(sizeof(BYTE) * dwHookLen);
	memcpy(g_pCodePatch, (LPVOID)dwHookAddr, dwHookLen);
	//��ȡҪ��ת�ĵ�ַ
	dwJmpCode = (DWORD)HookProc - dwHookAddr - 0x5;
	//��ʼ��HOOKλ���ڴ�(NOP->0x90)
	memset((PVOID)dwHookAddr, 0x90, dwHookLen);
	//�޸�HOOKλ��Ӳ����
	*((PBYTE)dwHookAddr) = 0xE9;
	*((PDWORD)(dwHookAddr + 0x1)) = dwJmpCode;
	//�޸�ȫ�ֱ���
	g_dwHookAddr = dwHookAddr;
	g_dwRetAddr = dwHookAddr + dwHookLen;
	g_dwHookLen = dwHookLen;
	g_bHookFlag = TRUE;
	//����
	return g_bHookFlag;


	return TRUE;
}

//ж��Inline HOOK
BOOL UnSetInlineHOOK()
{
	//�ж��Ƿ�HOOK�ɹ�
	if (!g_bHookFlag)
	{
		MessageBox(NULL,"��ǰû��HOOK��","[��ʾ]",MB_OK);
		return FALSE;
	}
	//д��ԭ����Ӳ����
	memcpy((LPVOID)g_dwHookAddr, g_pCodePatch, g_dwHookLen);
	//�ָ��ڴ�ҳ����
	VirtualProtect((LPVOID)g_dwHookAddr, g_dwHookLen, g_dwOldProtect, NULL);
	//�޸�ȫ�ֱ���
	g_bHookFlag = FALSE;
	free(g_pCodePatch);
	g_pCodePatch = NULL;
	g_dwHookLen = 0;
	g_dwHookAddr = 0;
	g_dwRetAddr = 0;
	//����
	return TRUE;
}