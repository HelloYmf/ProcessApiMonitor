/*
* API��ظ�������
*/

#pragma once
#include <Windows.h>
#include <CommCtrl.h>
#include <Tlhelp32.h>
#include "../ProcessMonitor1.0/resource.h"
#include "../PE Module/PeTools.h"
#include <stdio.h>
#pragma comment(lib,"comctl32.lib")


extern DWORD g_dwRowId;							//ѡ�еĺ���

extern HINSTANCE g_hAppInstance;				//�����ھ��
extern TCHAR* g_pModuleName;					//ģ����
extern TCHAR g_szProcName[0x80];				//��ѡ�н�����
extern DWORD g_dwChosedProcPid;					//��ѡ�н���PID
extern DWORD g_dwChosedProcAddr;				//��ѡ�н��̻�ַ
extern DWORD g_dwChosedProcSize;				//��ѡ�н���ģ���С
extern TCHAR g_szChosedFunName[0x80];			//��ѡ�к�������
extern TCHAR g_szChosedFunState[0x80];			//��ѡ�к���״̬
extern TCHAR g_szChosedFunDLL[0x80];			//��ѡ�к�������DLL
extern HANDLE hPipe;							//�����ܵ�

//ʮ�������ַ���->10������
int CharToInt(char ch);
int HexToDec(char* hex);
//����Դ��������ȡ�ļ�
TCHAR* GetFileName(HWND hwndDlg);
//��ʼ�����̱��ͷ
VOID InitProcessListHeader(HWND hwndDlg);
//��ʼ���������ͷ
VOID InitFunctionListHeader(HWND hwndDlg);
//��������
VOID EnumProcess(HWND hwndDlg);
//��ȡѡ�н�����Ϣ
VOID GetChosProcInfo(HWND hwndDlg);
//��ȡѡ�к�����Ϣ
VOID GetChosFunInfo(HWND hwndDlg);
//��ȡĳһ�б������
VOID GetRow(HWND hList);
//���ѡ�н��̱༭��
VOID FillChooseProcess(HWND hwndDlg);
//���������б�(INT)
BOOL EnumFunctions(HWND hwndDlg);
//ָ�����̿ռ���ָ����ַ�����ڴ�
LPVOID VirtualAllocate(HANDLE hProcess, PVOID pAddress, DWORD size_t);
//�ڴ�д�룬����ģ��ע��
BOOL InjectModule(char* ModulePath);