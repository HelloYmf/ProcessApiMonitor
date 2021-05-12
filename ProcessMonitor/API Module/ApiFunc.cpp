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
	//设置过滤器信息
	TCHAR szPeFileExt[30] = TEXT("*.exe;*.dll;*.sys");
	//保存文件名字缓冲区
	TCHAR* szFileName = (TCHAR*)malloc(sizeof(TCHAR) * 256);
	//初始化
	memset(szFileName, 0, 256);
	memset(&stOpenFile, 0, sizeof(OPENFILENAME));
	//设置参数
	stOpenFile.lStructSize = sizeof(OPENFILENAME);
	stOpenFile.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
	stOpenFile.hwndOwner = hwndDlg;
	stOpenFile.lpstrFilter = szPeFileExt;
	stOpenFile.lpstrFile = szFileName;
	stOpenFile.nMaxFile = MAX_PATH;
	//获取文件完整路径
	GetOpenFileName(&stOpenFile);
	return szFileName;
}

VOID InitProcessListHeader(HWND hwndDlg)
{
	LV_COLUMNA lv;
	HWND hListProcess;
	//初始化
	memset(&lv, 0, sizeof(LV_COLUMNA));
	//获取IDC_LIST_PROCESS句柄
	hListProcess = GetDlgItem(hwndDlg, IDC_LIST_PROCESS);
	//设置整行选中
	SendMessage(hListProcess, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);
	//设置样式
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	//设置第一列
	lv.pszText = (LPSTR)"进程";
	lv.cx = 195;
	lv.iSubItem = 0;
	SendMessage(hListProcess, LVM_INSERTCOLUMN, 0, (DWORD)&lv);
	//设置第二列
	lv.pszText = (LPSTR)"PID";
	lv.cx = 75;
	lv.iSubItem = 1;
	SendMessage(hListProcess, LVM_INSERTCOLUMN, 1, (DWORD)&lv);
	//设置第三列
	lv.pszText = (LPSTR)"基址";
	lv.cx = 75;
	lv.iSubItem = 2;
	SendMessage(hListProcess, LVM_INSERTCOLUMN, 2, (DWORD)&lv);
	//设置第四列
	lv.pszText = (LPSTR)"大小";
	lv.cx = 75;
	lv.iSubItem = 3;
	SendMessage(hListProcess, LVM_INSERTCOLUMN, 3, (DWORD)&lv);
}

VOID InitFunctionListHeader(HWND hwndDlg)
{
	LV_COLUMNA lv;
	HWND hListFunction;
	//初始化
	memset(&lv, 0, sizeof(LV_COLUMNA));
	//获取IDC_LIST_PROCESS句柄
	hListFunction = GetDlgItem(hwndDlg, IDC_LIST_FUNCTION);
	//设置整行选中
	SendMessage(hListFunction, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);
	//设置样式
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	//设置第一列
	lv.pszText = (LPSTR)"函数名/序号";
	lv.cx = 205;
	lv.iSubItem = 0;
	SendMessage(hListFunction, LVM_INSERTCOLUMN, 0, (DWORD)&lv);
	//设置第二列
	lv.pszText = (LPSTR)"导入方式";
	lv.cx = 105;
	lv.iSubItem = 1;
	SendMessage(hListFunction, LVM_INSERTCOLUMN, 1, (DWORD)&lv);
	//设置第三列
	lv.pszText = (LPSTR)"当前状态";
	lv.cx = 100;
	lv.iSubItem = 2;
	SendMessage(hListFunction, LVM_INSERTCOLUMN, 2, (DWORD)&lv);
	//设置第四列
	lv.pszText = (LPSTR)"所属DLL";
	lv.cx = 180;
	lv.iSubItem = 3;
	SendMessage(hListFunction, LVM_INSERTCOLUMN, 3, (DWORD)&lv);
}

VOID EnumProcess(HWND hwndDlg)
{
	LV_ITEM vitem;				//List的数据项
	HWND hListProcess;			//List句柄
	PROCESSENTRY32 pe32;		//进程信息结构
	MODULEENTRY32 me32;			//模块信息结构
	HANDLE hSnapshot_proc;		//进程快照句柄
	HANDLE hSnapshot_modl;		//模块快照句柄

	//初始化						
	memset(&vitem, 0, sizeof(LV_ITEM));
	memset(&pe32, 0, sizeof(PROCESSENTRY32));
	memset(&me32, 0, sizeof(MODULEENTRY32));
	//获取IDC_LIST_PROCESS句柄
	hListProcess = GetDlgItem(hwndDlg, IDC_LIST_PROCESS);

	//清空表中数据
	ListView_DeleteAllItems(hListProcess);

	//设置样式
	vitem.mask = LVIF_TEXT;

	//遍历系统进程
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
			//设置进程名字
			vitem.pszText = pe32.szExeFile;
			vitem.iItem = i;
			vitem.iSubItem = 0;
			ListView_InsertItem(hListProcess, &vitem);

			//设置进程PID
			TCHAR* cPid;
			cPid = (TCHAR*)malloc(sizeof(TCHAR) * 20);
			sprintf(cPid, "%08X", pe32.th32ProcessID);
			vitem.pszText = cPid;
			vitem.iSubItem = 1;
			ListView_SetItem(hListProcess, &vitem);

			//设置镜像基址和镜像大小
			hSnapshot_modl = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID);
			if (hSnapshot_modl != INVALID_HANDLE_VALUE)
			{
				Module32First(hSnapshot_modl, &me32);
				//镜像基址
				TCHAR* wBaseAddr;
				wBaseAddr = (TCHAR*)malloc(sizeof(TCHAR) * 20);
				sprintf(wBaseAddr, "%08X", me32.modBaseAddr);
				vitem.pszText = wBaseAddr;
				vitem.iSubItem = 2;
				ListView_SetItem(hListProcess, &vitem);
				//镜像大小
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
	//填充选中进程编辑框
	LV_ITEM vitem;						//List的数据项
	DWORD dwRowId;						//选中的行
	TCHAR szPid[0x80] = { 0 };			//存放PID的缓冲区
	TCHAR szAddr[0x80] = { 0 };			//存放基址的缓冲区
	TCHAR szSize[0x80] = { 0 };			//存放模块大小的缓冲区
	HWND hListProcess;					//ProcessList句柄
	//初始化
	memset(&vitem, 0, sizeof(LV_ITEM));
	//获取句柄
	hListProcess = GetDlgItem(hwndDlg, IDC_LIST_PROCESS);
	//清空编辑框内容
	SendDlgItemMessage(hwndDlg, IDC_EDIT_CHOOSEPROCESS, WM_SETTEXT, 0, 0);
	//获取选中行
	dwRowId = SendMessage(hListProcess, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
	if (dwRowId == -1)
	{
		MessageBox(NULL, TEXT("请选择进程！！！"), TEXT("提示"), MB_OK);
		return;
	}
	//获取进程名
	vitem.iSubItem = 0;				//要提取的列
	vitem.pszText = g_szProcName;	//指定存储查询结果的缓冲区
	vitem.cchTextMax = 0x80;		//要提取的尺寸
	SendMessage(hListProcess, LVM_GETITEMTEXT, dwRowId, (DWORD)&vitem);
	//获取PID
	vitem.iSubItem = 1;				//要提取的列
	vitem.pszText = szPid;			//指定存储查询结果的缓冲区
	vitem.cchTextMax = 0x80;		//要提取的尺寸
	SendMessage(hListProcess, LVM_GETITEMTEXT, dwRowId, (DWORD)&vitem);
	g_dwChosedProcPid = HexToDec(szPid);
	//获取进程基址
	vitem.iSubItem = 2;				//要提取的列
	vitem.pszText = szAddr;			//指定存储查询结果的缓冲区
	vitem.cchTextMax = 0x80;		//要提取的尺寸
	SendMessage(hListProcess, LVM_GETITEMTEXT, dwRowId, (DWORD)&vitem);
	g_dwChosedProcAddr = HexToDec(szAddr);
	//获取模块大小
	vitem.iSubItem = 3;				//要提取的列
	vitem.pszText = szSize;			//指定存储查询结果的缓冲区
	vitem.cchTextMax = 0x80;		//要提取的尺寸
	SendMessage(hListProcess, LVM_GETITEMTEXT, dwRowId, (DWORD)&vitem);
	g_dwChosedProcSize = HexToDec(szSize);
}

VOID GetRow(HWND hList)
{
	//获取选中行
	g_dwRowId = SendMessage(hList, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
}

VOID GetChosFunInfo(HWND hwndDlg)
{
	//填充选中进程编辑框
	LV_ITEM vitem;						//List的数据项
	TCHAR szName[0x80] = { 0 };			//存放函数名字的缓冲区
	TCHAR szState[0x80] = { 0 };		//存放函数状态的缓冲区
	TCHAR szDLL[0x80] = { 0 };			//存放所属DLL的缓冲区
	HWND hListFunction;					//FunctionList句柄
	//初始化
	memset(&vitem, 0, sizeof(LV_ITEM));
	//获取句柄
	hListFunction = GetDlgItem(hwndDlg, IDC_LIST_FUNCTION);
	//获取选中行
	//GetRow(hListFunction);
	if (g_dwRowId == -1)
	{
		MessageBox(NULL, TEXT("请选择函数！！！"), TEXT("提示"), MB_OK);
		return;
	}
	//获取函数名
	vitem.iSubItem = 0;				//要提取的列
	vitem.pszText = g_szChosedFunName;	//指定存储查询结果的缓冲区
	vitem.cchTextMax = 0x80;		//要提取的尺寸
	SendMessage(hListFunction, LVM_GETITEMTEXT, g_dwRowId, (DWORD)&vitem);
	//获取函数状态
	vitem.iSubItem = 2;				//要提取的列
	vitem.pszText = g_szChosedFunState;			//指定存储查询结果的缓冲区
	vitem.cchTextMax = 0x80;		//要提取的尺寸
	SendMessage(hListFunction, LVM_GETITEMTEXT, g_dwRowId, (DWORD)&vitem);
	//获取函数所属DLL
	vitem.iSubItem = 3;							//要提取的列
	vitem.pszText = g_szChosedFunDLL;			//指定存储查询结果的缓冲区
	vitem.cchTextMax = 0x80;					//要提取的尺寸
	SendMessage(hListFunction, LVM_GETITEMTEXT, g_dwRowId, (DWORD)&vitem);
}

VOID FillChooseProcess(HWND hwndDlg)
{
	//填充选中进程编辑框
	SendDlgItemMessage(hwndDlg, IDC_EDIT_CHOOSEPROCESS, WM_SETTEXT, 0, (DWORD)g_szProcName);
}

BOOL EnumFunctions(HWND hwndDlg)
{
	LV_ITEM vitem;				//List的数据项
	HWND hListFunction;			//List句柄-函数表
	memset(&vitem, 0, sizeof(LV_ITEM));
	//获取列表句柄
	hListFunction = GetDlgItem(hwndDlg, IDC_LIST_FUNCTION);
	//清空表中数据
	ListView_DeleteAllItems(hListFunction);
	//设置样式
	vitem.mask = LVIF_TEXT;
	//读取进程内存
	BYTE* pImageBuffer = (BYTE*)malloc(sizeof(BYTE) * g_dwChosedProcSize);
	HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, g_dwChosedProcPid);
	::ReadProcessMemory(hProcess, (LPVOID)g_dwChosedProcAddr, pImageBuffer, g_dwChosedProcSize, NULL);
	//生成pe对象
	PeInstance ChosedProc((HANDLE)pImageBuffer, 0, 0);
	//遍历导入表
		//获取导入表指针
	PIMAGE_IMPORT_DESCRIPTOR pImportDesriptor = (PIMAGE_IMPORT_DESCRIPTOR)(ChosedProc.OptionalHeader_Image->DataDirectory[1].VirtualAddress + (DWORD)ChosedProc.GetBufferInstance(1));
	if (!pImportDesriptor->OriginalFirstThunk && !pImportDesriptor)
	{
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
		for (int k = 0;; k++)
		{
			if (((PDWORD)(pTemp->OriginalFirstThunk + (DWORD)ChosedProc.GetBufferInstance(1)))[k] != 0)
			{
				if (!pTemp->TimeDateStamp)	//如果时间戳是0，说明没有绑定导入表
				{
					if (((PDWORD)(pTemp->OriginalFirstThunk + (DWORD)ChosedProc.GetBufferInstance(1)))[k] >> 0x1F == 1)
					{
						//序号导出
							//(LPCSTR)(((PDWORD)(pTemp->OriginalFirstThunk + (DWORD)ChosedProc.GetBufferInstance(1)))[k] & 0x7FFFFFFF)
						//设置导入序号
						TCHAR szOriBuffer[20] = { 0 };
						sprintf(szOriBuffer, "%0X", ((PDWORD)(pTemp->OriginalFirstThunk + (DWORD)ChosedProc.GetBufferInstance(1)))[k] & 0x7FFFFFFF);

						vitem.pszText = szOriBuffer;
						vitem.iItem = k;
						vitem.iSubItem = 0;
						ListView_InsertItem(hListFunction, &vitem);

						//设置来源
						vitem.pszText = (LPSTR)"序号";
						vitem.iSubItem = 1;
						ListView_SetItem(hListFunction, &vitem);

						//设置函数状态
						vitem.pszText = (LPSTR)"未被监控";
						vitem.iSubItem = 2;
						ListView_SetItem(hListFunction, &vitem);

						//设置所属DLL
						vitem.pszText = (LPSTR)(pTemp->Name + (DWORD)ChosedProc.GetBufferInstance(1));
						vitem.iSubItem = 3;
						ListView_SetItem(hListFunction, &vitem);
					}
					else
					{
						//设置函数名字
						vitem.pszText = ((PIMAGE_IMPORT_BY_NAME)(((PDWORD)(pTemp->OriginalFirstThunk + (DWORD)ChosedProc.GetBufferInstance(1)))[k] + (DWORD)ChosedProc.GetBufferInstance(1)))->Name;
						vitem.iItem = k;
						vitem.iSubItem = 0;
						ListView_InsertItem(hListFunction, &vitem);

						//设置来源
						vitem.pszText = (LPSTR)"名字";
						vitem.iSubItem = 1;
						ListView_SetItem(hListFunction, &vitem);

						//设置函数状态
						vitem.pszText = (LPSTR)"未被监控";
						vitem.iSubItem = 2;
						ListView_SetItem(hListFunction, &vitem);

						//设置所属DLL
						vitem.pszText = (LPSTR)(pTemp->Name + (DWORD)ChosedProc.GetBufferInstance(1));
						vitem.iSubItem = 3;
						ListView_SetItem(hListFunction, &vitem);

					}
				}
				else
				{
					printf("有绑定导入表，无需修复！\n");
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
		MessageBox(NULL, "Kernel加载失败！", "错误", MB_OK);
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
		//如果不成功, 这里会报487内存访问错误, 很正常, 因为申请源地址有东西
		//printf("GetLastError: %d\n", (int)GetLastError());
		//printf("ImageBase被占用, 将随机申请空间. 请修复重定位表");
		LPVOID newImageBase = NULL;
		if ((newImageBase = VirtualAllocEx(
			hProcess,
			NULL,
			size_t,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_EXECUTE_READWRITE
		)))
			return newImageBase;
		MessageBox(NULL, "没有足够空间！", "错误", MB_OK);
		return NULL;
	}

	FreeLibrary(hModuleKernel);
	return pAddress;
}

BOOL InjectModule(char* ModulePath)
{
	HMODULE hDll = LoadLibraryA("TestInjectDLL.dll");
	DWORD dwInjectEntry = (DWORD)GetProcAddress(hDll, "_InjectEntry@4");
	//加载PE文件
	PeInstance CurrentPe((PATH)ModulePath, 1);
	//拉伸PE
	CurrentPe.ToImageBuffer();
	//修复IAT表
	CurrentPe.FixIAT();
	//获取SizeOfImage和ImageBase
	DWORD dwSizeOfImage = CurrentPe.OptionalHeader_Image->SizeOfImage;
	DWORD dwImageBase = CurrentPe.OptionalHeader_Image->ImageBase;
	//获取进程句柄
	HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, g_dwChosedProcPid);
	//分配空间
	PBYTE DesAddr = (PBYTE)VirtualAllocate(hProcess, (PVOID)dwImageBase, dwSizeOfImage);
	//判断地址是否正确
	if (!DesAddr)
	{
		printf("内存分配失败!\n");
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
			MessageBox(NULL, "无重定位表！", "错误", MB_OK);
			return FALSE;
		}
	}
	//把修复后的数据复制进去
	DWORD WrittenBytes = 0;
	WriteProcessMemory(hProcess, DesAddr, CurrentPe.ImageBuffer, dwSizeOfImage, &WrittenBytes);
	if (!WrittenBytes)
	{
		MessageBox(NULL, "写入进程失败！", "错误", MB_OK);
		return FALSE;
	}
	//线程回调函数地址
	DWORD dwProcOffset = (DWORD)dwInjectEntry - (DWORD)hDll + (DWORD)DesAddr;
	//创建远程线程
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
		MessageBox(NULL, "远程线程创建失败！", "错误", MB_OK);
	}

	return TRUE;
}