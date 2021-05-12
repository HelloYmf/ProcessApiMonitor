#pragma once
#include <Windows.h>
#include "../Api Module/ApiFunc.h"

/*
*	进程通信相关函数
*/

//创建命名管道
BOOL CreatePipe(HANDLE& hPipe);

//打开命名管道
BOOL OpenPipe(HANDLE& hPipe, const char* PipeName);

//等待客户端连接
BOOL WaitConnectPipe(HANDLE& hPipe);

//客户端连接
BOOL ClientConnectPipe(const char* PipeName);

//关闭命名管道
VOID ClosePipe(HANDLE& hPipe);

//发送指令
/*
*	指令类型： 0 监控API
*			  1 停止监控API
*			  2 监控自定义位置
*             3 停止监控自定义位置
*             4 远程调用某个函数
*/
VOID SendShell(DWORD ShellType);

/*
*	进程其他函数
*/

//提权函数
BOOL EnableDebugPrivilege();
