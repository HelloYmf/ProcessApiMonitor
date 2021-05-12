#pragma once
#include <Windows.h>

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

/*
*	进程其他函数
*/

//提权函数
BOOL EnableDebugPrivilege();
