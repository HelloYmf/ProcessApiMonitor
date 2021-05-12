#include "ApiFunc.h"

int CharToInt(char ch)
{
	if (isdigit(ch))
		return ch - 48;
	if (ch < 'A' || (ch > 'F' && ch < 'a') || ch > 'z')
		return -1;
	if (isalpha(ch))
		return isupper(ch) ? ch - 55 : ch - 87;
	return -1;
}

int HexToDec(char* hex)
{
	int len;
	int num = 0;
	int temp;
	int bits;
	int i;
	len = strlen(hex);

	for (i = 0, temp = 0; i < len; i++, temp = 0)
	{
		temp = CharToInt(*(hex + i));
		bits = (len - i - 1) * 4;
		temp = temp << bits;
		num = num | temp;
	}
	return num;
}

TCHAR* GetFileName(HWND hwndDlg)
{
	OPENFILENAME stOpenFile;
	//���ù�������Ϣ
	TCHAR szPeFileExt[30] = TEXT("*.exe;*.dll;*.sys");
	//�����ļ����ֻ�����
	TCHAR* szFileName = (TCHAR*)malloc(sizeof(TCHAR) * 256);
	//��ʼ��
	memset(szFileName, 0, 256);
	memset(&stOpenFile, 0, sizeof(OPENFILENAME));
	//���ò���
	stOpenFile.lStructSize = sizeof(OPENFILENAME);
	stOpenFile.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
	stOpenFile.hwndOwner = hwndDlg;
	stOpenFile.lpstrFilter = szPeFileExt;
	stOpenFile.lpstrFile = szFileName;
	stOpenFile.nMaxFile = MAX_PATH;
	//��ȡ�ļ�����·��
	GetOpenFileName(&stOpenFile);
	return szFileName;
}

VOID InitProcessListHeader(HWND hwndDlg)
{
	LV_COLUMNA lv;
	HWND hListProcess;
	//��ʼ��
	memset(&lv, 0, sizeof(LV_COLUMNA));
	//��ȡIDC_LIST_PROCESS���
	hListProcess = GetDlgItem(hwndDlg, IDC_LIST_PROCESS);
	//��������ѡ��
	SendMessage(hListProcess, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);
	//������ʽ
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	//���õ�һ��
	lv.pszText = (LPSTR)"����";
	lv.cx = 195;
	lv.iSubItem = 0;
	SendMessage(hListProcess, LVM_INSERTCOLUMN, 0, (DWORD)&lv);
	//���õڶ���
	lv.pszText = (LPSTR)"PID";
	lv.cx = 75;
	lv.iSubItem = 1;
	SendMessage(hListProcess, LVM_INSERTCOLUMN, 1, (DWORD)&lv);
	//���õ�����
	lv.pszText = (LPSTR)"��ַ";
	lv.cx = 75;
	lv.iSubItem = 2;
	SendMessage(hListProcess, LVM_INSERTCOLUMN, 2, (DWORD)&lv);
	//���õ�����
	lv.pszText = (LPSTR)"��С";
	lv.cx = 75;
	lv.iSubItem = 3;
	SendMessage(hListProcess, LVM_INSERTCOLUMN, 3, (DWORD)&lv);
}

VOID InitFunctionListHeader(HWND hwndDlg)
{
	LV_COLUMNA lv;
	HWND hListFunction;
	//��ʼ��
	memset(&lv, 0, sizeof(LV_COLUMNA));
	//��ȡIDC_LIST_PROCESS���
	hListFunction = GetDlgItem(hwndDlg, IDC_LIST_FUNCTION);
	//��������ѡ��
	SendMessage(hListFunction, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);
	//������ʽ
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	//���õ�һ��
	lv.pszText = (LPSTR)"������/���";
	lv.cx = 205;
	lv.iSubItem = 0;
	SendMessage(hListFunction, LVM_INSERTCOLUMN, 0, (DWORD)&lv);
	//���õڶ���
	lv.pszText = (LPSTR)"���뷽ʽ";
	lv.cx = 105;
	lv.iSubItem = 1;
	SendMessage(hListFunction, LVM_INSERTCOLUMN, 1, (DWORD)&lv);
	//���õ�����
	lv.pszText = (LPSTR)"��ǰ״̬";
	lv.cx = 100;
	lv.iSubItem = 2;
	SendMessage(hListFunction, LVM_INSERTCOLUMN, 2, (DWORD)&lv);
	//���õ�����
	lv.pszText = (LPSTR)"����DLL";
	lv.cx = 180;
	lv.iSubItem = 3;
	SendMessage(hListFunction, LVM_INSERTCOLUMN, 3, (DWORD)&lv);
}

VOID EnumProcess(HWND hwndDlg)
{
	LV_ITEM vitem;				//List��������
	HWND hListProcess;			//List���
	PROCESSENTRY32 pe32;		//������Ϣ�ṹ
	MODULEENTRY32 me32;			//ģ����Ϣ�ṹ
	HANDLE hSnapshot_proc;		//���̿��վ��
	HANDLE hSnapshot_modl;		//ģ����վ��

	//��ʼ��						
	memset(&vitem, 0, sizeof(LV_ITEM));
	memset(&pe32, 0, sizeof(PROCESSENTRY32));
	memset(&me32, 0, sizeof(MODULEENTRY32));
	//��ȡIDC_LIST_PROCESS���
	hListProcess = GetDlgItem(hwndDlg, IDC_LIST_PROCESS);

	//��ձ�������
	ListView_DeleteAllItems(hListProcess);

	//������ʽ
	vitem.mask = LVIF_TEXT;

	//����ϵͳ����
	me32.dwSize = sizeof(me32);
	pe32.dwSize = sizeof(pe32);
	hSnapshot_proc = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot_proc != INVALID_HANDLE_VALUE)
	{
		BOOL check1 = Process32First(hSnapshot_proc, &pe32);
		int i = 0;
		while (check1)
		{
			if (pe32.th32ProcessID == 0)
			{
				check1 = Process32Next(hSnapshot_proc, &pe32);
				continue;
			}
			//���ý�������
			vitem.pszText = pe32.szExeFile;
			vitem.iItem = i;
			vitem.iSubItem = 0;
			ListView_InsertItem(hListProcess, &vitem);

			//���ý���PID
			TCHAR* cPid;
			cPid = (TCHAR*)malloc(sizeof(TCHAR) * 20);
			sprintf(cPid, "%08X", pe32.th32ProcessID);
			vitem.pszText = cPid;
			vitem.iSubItem = 1;
			ListView_SetItem(hListProcess, &vitem);

			//���þ����ַ�;����С
			hSnapshot_modl = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID);
			if (hSnapshot_modl != INVALID_HANDLE_VALUE)
			{
				Module32First(hSnapshot_modl, &me32);
				//�����ַ
				TCHAR* wBaseAddr;
				wBaseAddr = (TCHAR*)malloc(sizeof(TCHAR) * 20);
				sprintf(wBaseAddr, "%08X", me32.modBaseAddr);
				vitem.pszText = wBaseAddr;
				vitem.iSubItem = 2;
				ListView_SetItem(hListProcess, &vitem);
				//�����С
				TCHAR* wBaseSize;
				wBaseSize = (TCHAR*)malloc(sizeof(TCHAR) * 20);
				sprintf(wBaseSize, "%08X", me32.modBaseSize);
				vitem.pszText = wBaseSize;
				vitem.iSubItem = 3;
				ListView_SetItem(hListProcess, &vitem);
			}
			else
			{
				vitem.pszText = (LPSTR)"0";
				vitem.iSubItem = 2;
				ListView_SetItem(hListProcess, &vitem);
				vitem.iSubItem = 3;
				ListView_SetItem(hListProcess, &vitem);
			}

			check1 = Process32Next(hSnapshot_proc, &pe32);
			i++;
		}
	}
	CloseHandle(hSnapshot_proc);
}

VOID GetChosProcInfo(HWND hwndDlg)
{
	//���ѡ�н��̱༭��
	LV_ITEM vitem;						//List��������
	DWORD dwRowId;						//ѡ�е���
	TCHAR szPid[0x80] = { 0 };			//���PID�Ļ�����
	TCHAR szAddr[0x80] = { 0 };			//��Ż�ַ�Ļ�����
	TCHAR szSize[0x80] = { 0 };			//���ģ���С�Ļ�����
	HWND hListProcess;					//ProcessList���
	//��ʼ��
	memset(&vitem, 0, sizeof(LV_ITEM));
	//��ȡ���
	hListProcess = GetDlgItem(hwndDlg, IDC_LIST_PROCESS);
	//��ձ༭������
	SendDlgItemMessage(hwndDlg, IDC_EDIT_CHOOSEPROCESS, WM_SETTEXT, 0, 0);
	//��ȡѡ����
	dwRowId = SendMessage(hListProcess, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
	if (dwRowId == -1)
	{
		MessageBox(NULL, TEXT("��ѡ����̣�����"), TEXT("��ʾ"), MB_OK);
		return;
	}
	//��ȡ������
	vitem.iSubItem = 0;				//Ҫ��ȡ����
	vitem.pszText = g_szProcName;	//ָ���洢��ѯ����Ļ�����
	vitem.cchTextMax = 0x80;		//Ҫ��ȡ�ĳߴ�
	SendMessage(hListProcess, LVM_GETITEMTEXT, dwRowId, (DWORD)&vitem);
	//��ȡPID
	vitem.iSubItem = 1;				//Ҫ��ȡ����
	vitem.pszText = szPid;			//ָ���洢��ѯ����Ļ�����
	vitem.cchTextMax = 0x80;		//Ҫ��ȡ�ĳߴ�
	SendMessage(hListProcess, LVM_GETITEMTEXT, dwRowId, (DWORD)&vitem);
	g_dwChosedProcPid = HexToDec(szPid);
	//��ȡ���̻�ַ
	vitem.iSubItem = 2;				//Ҫ��ȡ����
	vitem.pszText = szAddr;			//ָ���洢��ѯ����Ļ�����
	vitem.cchTextMax = 0x80;		//Ҫ��ȡ�ĳߴ�
	SendMessage(hListProcess, LVM_GETITEMTEXT, dwRowId, (DWORD)&vitem);
	g_dwChosedProcAddr = HexToDec(szAddr);
	//��ȡģ���С
	vitem.iSubItem = 3;				//Ҫ��ȡ����
	vitem.pszText = szSize;			//ָ���洢��ѯ����Ļ�����
	vitem.cchTextMax = 0x80;		//Ҫ��ȡ�ĳߴ�
	SendMessage(hListProcess, LVM_GETITEMTEXT, dwRowId, (DWORD)&vitem);
	g_dwChosedProcSize = HexToDec(szSize);
}

VOID GetRow(HWND hList)
{
	//��ȡѡ����
	g_dwRowId = SendMessage(hList, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
}

VOID GetChosFunInfo(HWND hwndDlg)
{
	//���ѡ�н��̱༭��
	LV_ITEM vitem;						//List��������
	TCHAR szName[0x80] = { 0 };			//��ź������ֵĻ�����
	TCHAR szState[0x80] = { 0 };		//��ź���״̬�Ļ�����
	TCHAR szDLL[0x80] = { 0 };			//�������DLL�Ļ�����
	HWND hListFunction;					//FunctionList���
	//��ʼ��
	memset(&vitem, 0, sizeof(LV_ITEM));
	//��ȡ���
	hListFunction = GetDlgItem(hwndDlg, IDC_LIST_FUNCTION);
	//��ȡѡ����
	//GetRow(hListFunction);
	if (g_dwRowId == -1)
	{
		MessageBox(NULL, TEXT("��ѡ����������"), TEXT("��ʾ"), MB_OK);
		return;
	}
	//��ȡ������
	vitem.iSubItem = 0;				//Ҫ��ȡ����
	vitem.pszText = g_szChosedFunName;	//ָ���洢��ѯ����Ļ�����
	vitem.cchTextMax = 0x80;		//Ҫ��ȡ�ĳߴ�
	SendMessage(hListFunction, LVM_GETITEMTEXT, g_dwRowId, (DWORD)&vitem);
	//��ȡ����״̬
	vitem.iSubItem = 2;				//Ҫ��ȡ����
	vitem.pszText = g_szChosedFunState;			//ָ���洢��ѯ����Ļ�����
	vitem.cchTextMax = 0x80;		//Ҫ��ȡ�ĳߴ�
	SendMessage(hListFunction, LVM_GETITEMTEXT, g_dwRowId, (DWORD)&vitem);
	//��ȡ��������DLL
	vitem.iSubItem = 3;							//Ҫ��ȡ����
	vitem.pszText = g_szChosedFunDLL;			//ָ���洢��ѯ����Ļ�����
	vitem.cchTextMax = 0x80;					//Ҫ��ȡ�ĳߴ�
	SendMessage(hListFunction, LVM_GETITEMTEXT, g_dwRowId, (DWORD)&vitem);
}

VOID FillChooseProcess(HWND hwndDlg)
{
	//���ѡ�н��̱༭��
	SendDlgItemMessage(hwndDlg, IDC_EDIT_CHOOSEPROCESS, WM_SETTEXT, 0, (DWORD)g_szProcName);
}

BOOL EnumFunctions(HWND hwndDlg)
{
	LV_ITEM vitem;				//List��������
	HWND hListFunction;			//List���-������
	memset(&vitem, 0, sizeof(LV_ITEM));
	//��ȡ�б���
	hListFunction = GetDlgItem(hwndDlg, IDC_LIST_FUNCTION);
	//��ձ�������
	ListView_DeleteAllItems(hListFunction);
	//������ʽ
	vitem.mask = LVIF_TEXT;
	//��ȡ�����ڴ�
	BYTE* pImageBuffer = (BYTE*)malloc(sizeof(BYTE) * g_dwChosedProcSize);
	HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, g_dwChosedProcPid);
	::ReadProcessMemory(hProcess, (LPVOID)g_dwChosedProcAddr, pImageBuffer, g_dwChosedProcSize, NULL);
	//����pe����
	PeInstance ChosedProc((HANDLE)pImageBuffer, 0, 0);
	//���������
		//��ȡ�����ָ��
	PIMAGE_IMPORT_DESCRIPTOR pImportDesriptor = (PIMAGE_IMPORT_DESCRIPTOR)(ChosedProc.OptionalHeader_Image->DataDirectory[1].VirtualAddress + (DWORD)ChosedProc.GetBufferInstance(1));
	if (!pImportDesriptor->OriginalFirstThunk && !pImportDesriptor)
	{
		return FALSE;
	}
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
		//�жϵ�������
		for (int j = 0; j < sizeof(IMAGE_IMPORT_DESCRIPTOR); j++)
		{
			if (((PBYTE)pTemp)[j] != 0)
			{
				flag = 1;
				break;
			}
		}
		for (int k = 0;; k++)
		{
			if (((PDWORD)(pTemp->OriginalFirstThunk + (DWORD)ChosedProc.GetBufferInstance(1)))[k] != 0)
			{
				if (!pTemp->TimeDateStamp)	//���ʱ�����0��˵��û�а󶨵����
				{
					if (((PDWORD)(pTemp->OriginalFirstThunk + (DWORD)ChosedProc.GetBufferInstance(1)))[k] >> 0x1F == 1)
					{
						//��ŵ���
							//(LPCSTR)(((PDWORD)(pTemp->OriginalFirstThunk + (DWORD)ChosedProc.GetBufferInstance(1)))[k] & 0x7FFFFFFF)
						//���õ������
						TCHAR szOriBuffer[20] = { 0 };
						sprintf(szOriBuffer, "%0X", ((PDWORD)(pTemp->OriginalFirstThunk + (DWORD)ChosedProc.GetBufferInstance(1)))[k] & 0x7FFFFFFF);

						vitem.pszText = szOriBuffer;
						vitem.iItem = k;
						vitem.iSubItem = 0;
						ListView_InsertItem(hListFunction, &vitem);

						//������Դ
						vitem.pszText = (LPSTR)"���";
						vitem.iSubItem = 1;
						ListView_SetItem(hListFunction, &vitem);

						//���ú���״̬
						vitem.pszText = (LPSTR)"δ�����";
						vitem.iSubItem = 2;
						ListView_SetItem(hListFunction, &vitem);

						//��������DLL
						vitem.pszText = (LPSTR)(pTemp->Name + (DWORD)ChosedProc.GetBufferInstance(1));
						vitem.iSubItem = 3;
						ListView_SetItem(hListFunction, &vitem);
					}
					else
					{
						//���ú�������
						vitem.pszText = ((PIMAGE_IMPORT_BY_NAME)(((PDWORD)(pTemp->OriginalFirstThunk + (DWORD)ChosedProc.GetBufferInstance(1)))[k] + (DWORD)ChosedProc.GetBufferInstance(1)))->Name;
						vitem.iItem = k;
						vitem.iSubItem = 0;
						ListView_InsertItem(hListFunction, &vitem);

						//������Դ
						vitem.pszText = (LPSTR)"����";
						vitem.iSubItem = 1;
						ListView_SetItem(hListFunction, &vitem);

						//���ú���״̬
						vitem.pszText = (LPSTR)"δ�����";
						vitem.iSubItem = 2;
						ListView_SetItem(hListFunction, &vitem);

						//��������DLL
						vitem.pszText = (LPSTR)(pTemp->Name + (DWORD)ChosedProc.GetBufferInstance(1));
						vitem.iSubItem = 3;
						ListView_SetItem(hListFunction, &vitem);

					}
				}
				else
				{
					printf("�а󶨵���������޸���\n");
				}
			}
			else
			{
				break;
			}
		}
		pTemp++;
	}
}

LPVOID VirtualAllocate(HANDLE hProcess, PVOID pAddress, DWORD size_t)
{
	HMODULE hModuleKernel = LoadLibraryA("kernel32.dll");
	if (!hModuleKernel)
	{
		MessageBox(NULL, "Kernel����ʧ�ܣ�", "����", MB_OK);
		TerminateProcess(hProcess, 1);
		return NULL;
	}
	typedef void* (__stdcall* pfVirtualAllocEx)(
		HANDLE hProcess,
		LPVOID lpAddress,
		DWORD dwSize,
		DWORD flAllocationType,
		DWORD flProtect);
	pfVirtualAllocEx VirtualAllocEx = NULL;
	VirtualAllocEx = (pfVirtualAllocEx)GetProcAddress((hModuleKernel), "VirtualAllocEx");
	if (!VirtualAllocEx(
		hProcess,
		pAddress,
		size_t,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE
	))
	{
		//������ɹ�, ����ᱨ487�ڴ���ʴ���, ������, ��Ϊ����Դ��ַ�ж���
		//printf("GetLastError: %d\n", (int)GetLastError());
		//printf("ImageBase��ռ��, ���������ռ�. ���޸��ض�λ��");
		LPVOID newImageBase = NULL;
		if ((newImageBase = VirtualAllocEx(
			hProcess,
			NULL,
			size_t,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_EXECUTE_READWRITE
		)))
			return newImageBase;
		MessageBox(NULL, "û���㹻�ռ䣡", "����", MB_OK);
		return NULL;
	}

	FreeLibrary(hModuleKernel);
	return pAddress;
}

BOOL InjectModule(char* ModulePath)
{
	HMODULE hDll = LoadLibraryA("TestInjectDLL.dll");
	DWORD dwInjectEntry = (DWORD)GetProcAddress(hDll, "_InjectEntry@4");
	//����PE�ļ�
	PeInstance CurrentPe((PATH)ModulePath, 1);
	//����PE
	CurrentPe.ToImageBuffer();
	//�޸�IAT��
	CurrentPe.FixIAT();
	//��ȡSizeOfImage��ImageBase
	DWORD dwSizeOfImage = CurrentPe.OptionalHeader_Image->SizeOfImage;
	DWORD dwImageBase = CurrentPe.OptionalHeader_Image->ImageBase;
	//��ȡ���̾��
	HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, g_dwChosedProcPid);
	//����ռ�
	PBYTE DesAddr = (PBYTE)VirtualAllocate(hProcess, (PVOID)dwImageBase, dwSizeOfImage);
	//�жϵ�ַ�Ƿ���ȷ
	if (!DesAddr)
	{
		printf("�ڴ����ʧ��!\n");
		return FALSE;
	}
	if ((DWORD)DesAddr != dwImageBase)
	{
		if (CurrentPe.HaveRelocation(0))
		{
			CurrentPe.FixRelocation((DWORD)DesAddr, 0);
		}
		else
		{
			MessageBox(NULL, "���ض�λ��", "����", MB_OK);
			return FALSE;
		}
	}
	//���޸�������ݸ��ƽ�ȥ
	DWORD WrittenBytes = 0;
	WriteProcessMemory(hProcess, DesAddr, CurrentPe.ImageBuffer, dwSizeOfImage, &WrittenBytes);
	if (!WrittenBytes)
	{
		MessageBox(NULL, "д�����ʧ�ܣ�", "����", MB_OK);
		return FALSE;
	}
	//�̻߳ص�������ַ
	DWORD dwProcOffset = (DWORD)dwInjectEntry - (DWORD)hDll + (DWORD)DesAddr;
	//����Զ���߳�
	HANDLE myThread = CreateRemoteThread(
		hProcess,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)dwProcOffset,
		DesAddr,
		0,
		NULL
	);

	if (!myThread)
	{
		MessageBox(NULL, "Զ���̴߳���ʧ�ܣ�", "����", MB_OK);
	}

	return TRUE;
}