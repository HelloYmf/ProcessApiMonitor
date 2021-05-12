#pragma once
#include <Windows.h>
#include "../Api Module/ApiFunc.h"

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

//����ָ��
/*
*	ָ�����ͣ� 0 ���API
*			  1 ֹͣ���API
*			  2 ����Զ���λ��
*             3 ֹͣ����Զ���λ��
*             4 Զ�̵���ĳ������
*/
VOID SendShell(DWORD ShellType);

/*
*	������������
*/

//��Ȩ����
BOOL EnableDebugPrivilege();
