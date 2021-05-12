#pragma once
#include <Windows.h>

/*
*	����ͨ����غ���
*/

//���������ܵ�
BOOL CreatePipe(HANDLE& hPipe);

//�������ܵ�
BOOL OpenPipe(HANDLE& hPipe, const char* PipeName);

//�ȴ��ͻ�������
BOOL WaitConnectPipe(HANDLE& hPipe);

//�ͻ�������
BOOL ClientConnectPipe(const char* PipeName);

//�ر������ܵ�
VOID ClosePipe(HANDLE& hPipe);

/*
*	������������
*/

//��Ȩ����
BOOL EnableDebugPrivilege();
