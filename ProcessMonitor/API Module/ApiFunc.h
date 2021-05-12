/*
* API相关辅助函数
*/

#pragma once
#include <Windows.h>
#include <CommCtrl.h>
#include <Tlhelp32.h>
#include "../ProcessMonitor1.0/resource.h"
#include "../PE Module/PeTools.h"
#include <stdio.h>
#pragma comment(lib,"comctl32.lib")


extern DWORD g_dwRowId;							//选中的函数

extern HINSTANCE g_hAppInstance;				//主窗口句柄
extern TCHAR* g_pModuleName;					//模块名
extern TCHAR g_szProcName[0x80];				//被选中进程名
extern DWORD g_dwChosedProcPid;					//被选中进程PID
extern DWORD g_dwChosedProcAddr;				//被选中进程基址
extern DWORD g_dwChosedProcSize;				//被选中进程模块大小
extern TCHAR g_szChosedFunName[0x80];			//被选中函数名字
extern TCHAR g_szChosedFunState[0x80];			//被选中函数状态
extern TCHAR g_szChosedFunDLL[0x80];			//被选中函数所属DLL
extern HANDLE hPipe;							//命名管道

//十六进制字符串->10进制数
int CharToInt(char ch);
int HexToDec(char* hex);
//打开资源管理器获取文件
TCHAR* GetFileName(HWND hwndDlg);
//初始化进程表表头
VOID InitProcessListHeader(HWND hwndDlg);
//初始化函数表表头
VOID InitFunctionListHeader(HWND hwndDlg);
//遍历进程
VOID EnumProcess(HWND hwndDlg);
//获取选中进程信息
VOID GetChosProcInfo(HWND hwndDlg);
//获取选中函数信息
VOID GetChosFunInfo(HWND hwndDlg);
//获取某一列表的行数
VOID GetRow(HWND hList);
//填充选中进程编辑框
VOID FillChooseProcess(HWND hwndDlg);
//遍历函数列表(INT)
BOOL EnumFunctions(HWND hwndDlg);
//指定进程空间中指定地址分配内存
LPVOID VirtualAllocate(HANDLE hProcess, PVOID pAddress, DWORD size_t);
//内存写入，隐藏模块注入
BOOL InjectModule(char* ModulePath);