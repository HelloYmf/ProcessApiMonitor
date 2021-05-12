#include "PeTools.h"

PeInstance::PeInstance(HANDLE PeAddr, int flag ,size_t fileSize)
{
	//��ȡ����ָ��
	PBYTE pTemp = (PBYTE)PeAddr;
	DosHeader = (PIMAGE_DOS_HEADER)pTemp;							//��ȡDOSͷ
	pTemp = pTemp + ((PIMAGE_DOS_HEADER)pTemp)->e_lfanew;			//ƫ�Ƶ�NTͷ
	NtHeader = (PIMAGE_NT_HEADERS)pTemp;							//��ȡNTͷ
	pTemp = pTemp + 0x4;											//ƫ�Ƶ���׼PEͷ
	FileHeader = (PIMAGE_FILE_HEADER)pTemp;							//��ȡ��׼PEͷ
	pTemp = pTemp + 0x14;											//ƫ�Ƶ���ѡPEͷ
	OptionalHeader = (PIMAGE_OPTIONAL_HEADER)pTemp;					//��ȡ��ѡPEͷ
	pTemp = pTemp + FileHeader->SizeOfOptionalHeader;				//ƫ�Ƶ��ڱ�
	pSectionHeader = (PIMAGE_SECTION_HEADER)pTemp;					//��ȡ�ڱ�
	if (flag == 0)
	{
		FileSize = OptionalHeader->SizeOfImage;
		//����ڴ滺����
		ImageBuffer.AllocMem(OptionalHeader->SizeOfImage);
		ImageBuffer.used = OptionalHeader->SizeOfImage;
		memcpy(ImageBuffer, (PBYTE)PeAddr, OptionalHeader->SizeOfImage);

		//��ȡ����ָ��
		PBYTE pImageTemp = (PBYTE)ImageBuffer;
		DosHeader_Image = (PIMAGE_DOS_HEADER)pImageTemp;					//��ȡDOSͷ
		pImageTemp = pImageTemp + ((PIMAGE_DOS_HEADER)pImageTemp)->e_lfanew;	//ƫ�Ƶ�NTͷ
		NtHeader_Image = (PIMAGE_NT_HEADERS)pImageTemp;					//��ȡNTͷ
		pImageTemp = pImageTemp + 0x4;									//ƫ�Ƶ���׼PEͷ
		FileHeader_Image = (PIMAGE_FILE_HEADER)pImageTemp;					//��ȡ��׼PEͷ
		pImageTemp = pImageTemp + 0x14;									//ƫ�Ƶ���ѡPEͷ
		OptionalHeader_Image = (PIMAGE_OPTIONAL_HEADER)pImageTemp;			//��ȡ��ѡPEͷ
		pImageTemp = pImageTemp + FileHeader_Image->SizeOfOptionalHeader;		//ƫ�Ƶ��ڱ�
		pSectionHeader_Image = (PIMAGE_SECTION_HEADER)pImageTemp;			//��ȡ�ڱ�
	}
	else
	{
		FileSize = fileSize;
		//����ļ�������
		FileBuffer.AllocMem(fileSize);
		FileBuffer.used = fileSize;
		memcpy(FileBuffer, (PBYTE)PeAddr, fileSize);

		//���¸���ָ��
		PBYTE pFileTemp = (PBYTE)FileBuffer;
		DosHeader = (PIMAGE_DOS_HEADER)pFileTemp;					//��ȡDOSͷ
		pFileTemp = pFileTemp + ((PIMAGE_DOS_HEADER)pFileTemp)->e_lfanew;	//ƫ�Ƶ�NTͷ
		NtHeader = (PIMAGE_NT_HEADERS)pFileTemp;					//��ȡNTͷ
		pFileTemp = pFileTemp + 0x4;									//ƫ�Ƶ���׼PEͷ
		FileHeader = (PIMAGE_FILE_HEADER)pFileTemp;					//��ȡ��׼PEͷ
		pFileTemp = pFileTemp + 0x14;									//ƫ�Ƶ���ѡPEͷ
		OptionalHeader = (PIMAGE_OPTIONAL_HEADER)pFileTemp;			//��ȡ��ѡPEͷ
		pFileTemp = pFileTemp + FileHeader->SizeOfOptionalHeader;		//ƫ�Ƶ��ڱ�
		pSectionHeader = (PIMAGE_SECTION_HEADER)pFileTemp;			//��ȡ�ڱ�
	}
}

PeInstance::PeInstance(PATH path, int flag)
{
	//��PE�ļ�
	Cfile PeFile(path,1);
	FileSize = PeFile.size();
	PBYTE pTemp = NULL;
	switch (flag)
	{
		case 1:
		{
			//д��FileBuffer
			FileBuffer.AllocMem(FileSize);
			FileBuffer.used = FileSize;
			PeFile >> FileBuffer;
			//��ȡ����ָ��
			pTemp = FileBuffer;
			DosHeader = (PIMAGE_DOS_HEADER)pTemp;					//��ȡDOSͷ
			pTemp = pTemp + ((PIMAGE_DOS_HEADER)pTemp)->e_lfanew;	//ƫ�Ƶ�NTͷ
			NtHeader = (PIMAGE_NT_HEADERS)pTemp;					//��ȡNTͷ
			pTemp = pTemp + 0x4;									//ƫ�Ƶ���׼PEͷ
			FileHeader = (PIMAGE_FILE_HEADER)pTemp;					//��ȡ��׼PEͷ
			pTemp = pTemp + 0x14;									//ƫ�Ƶ���ѡPEͷ
			OptionalHeader = (PIMAGE_OPTIONAL_HEADER)pTemp;			//��ȡ��ѡPEͷ
			pTemp = pTemp + FileHeader->SizeOfOptionalHeader;		//ƫ�Ƶ��ڱ�
			pSectionHeader = (PIMAGE_SECTION_HEADER)pTemp;			//��ȡ�ڱ�
			break;
		}
		case 0:
		{
			//д��ImageBuffer
			ImageBuffer.AllocMem(FileSize);
			ImageBuffer.used = FileSize;
			PeFile >> ImageBuffer;
			//��ȡ����ָ��
			pTemp = ImageBuffer;
			DosHeader_Image = (PIMAGE_DOS_HEADER)pTemp;					//��ȡDOSͷ
			pTemp = pTemp + ((PIMAGE_DOS_HEADER)pTemp)->e_lfanew;	//ƫ�Ƶ�NTͷ
			NtHeader_Image = (PIMAGE_NT_HEADERS)pTemp;					//��ȡNTͷ
			pTemp = pTemp + 0x4;									//ƫ�Ƶ���׼PEͷ
			FileHeader_Image = (PIMAGE_FILE_HEADER)pTemp;					//��ȡ��׼PEͷ
			pTemp = pTemp + 0x14;									//ƫ�Ƶ���ѡPEͷ
			OptionalHeader_Image = (PIMAGE_OPTIONAL_HEADER)pTemp;			//��ȡ��ѡPEͷ
			pTemp = pTemp + FileHeader_Image->SizeOfOptionalHeader;		//ƫ�Ƶ��ڱ�
			pSectionHeader_Image = (PIMAGE_SECTION_HEADER)pTemp;			//��ȡ�ڱ�
			break;
		}
	}
}

BOOL PeInstance::ToImageBuffer()
{
	if (!FileBuffer || !DosHeader)
	{
		return FALSE;	//FileBuffer������
	}
	//���뻺����
	ImageBuffer.AllocMem(OptionalHeader->SizeOfImage);
	ImageBuffer.used = OptionalHeader->SizeOfImage;
	//��������ͷ+�ڱ�
	ImageBuffer.copy_from(FileBuffer, OptionalHeader->SizeOfHeaders, 0);
	//�������н�
	for (int j = 0; j < FileHeader->NumberOfSections; j++)
	{
		for (DWORD k = 0; k < pSectionHeader[j].SizeOfRawData; k++)
		{
			((PBYTE)ImageBuffer + pSectionHeader[j].VirtualAddress)[k] = ((PBYTE)FileBuffer + pSectionHeader[j].PointerToRawData)[k];
		}
	}
	//��ȡ_Imageָ��
	PBYTE pTemp = ImageBuffer;
	DosHeader_Image = (PIMAGE_DOS_HEADER)pTemp;					//��ȡDOSͷ
	pTemp = pTemp + ((PIMAGE_DOS_HEADER)pTemp)->e_lfanew;		//ƫ�Ƶ�NTͷ
	NtHeader_Image = (PIMAGE_NT_HEADERS)pTemp;					//��ȡNTͷ
	pTemp = pTemp + 0x4;										//ƫ�Ƶ���׼PEͷ
	FileHeader_Image = (PIMAGE_FILE_HEADER)pTemp;				//��ȡ��׼PEͷ
	pTemp = pTemp + 0x14;										//ƫ�Ƶ���ѡPEͷ
	OptionalHeader_Image = (PIMAGE_OPTIONAL_HEADER)pTemp;		//��ȡ��ѡPEͷ
	pTemp = pTemp + FileHeader_Image->SizeOfOptionalHeader;		//ƫ�Ƶ��ڱ�
	pSectionHeader_Image = (PIMAGE_SECTION_HEADER)pTemp;		//��ȡ�ڱ�
	//���سɹ���־
	return TRUE;
}

BOOL PeInstance::AddSeaction(size_t SectionSize)
{
	//����������
	BYTE NewSectionName[] = "Fly";
	//ΪNewBuffer����ռ�
	NewBuffer.AllocMem(FileSize + Align(SectionSize, OptionalHeader->FileAlignment));
	//��ԭ�������ݿ�������
	NewBuffer.used = FileSize + Align(SectionSize, OptionalHeader->FileAlignment);
	NewBuffer.copy_from(FileBuffer, FileSize);
	//��������ָ��
	PBYTE pNewBuffer = NewBuffer;
	DosHeader = (PIMAGE_DOS_HEADER)pNewBuffer;					//��ȡDOSͷ
	pNewBuffer = pNewBuffer + DosHeader->e_lfanew;				//ƫ�Ƶ�NTͷ
	NtHeader = (PIMAGE_NT_HEADERS)pNewBuffer;					//��ȡNTͷ
	pNewBuffer = pNewBuffer + 0x4;								//ƫ�Ƶ���׼PEͷ
	FileHeader = (PIMAGE_FILE_HEADER)pNewBuffer;				//��ȡ��׼PEͷ
	pNewBuffer = pNewBuffer + 0x14;								//ƫ�Ƶ���ѡPEͷ
	OptionalHeader = (PIMAGE_OPTIONAL_HEADER)pNewBuffer;		//��ȡ��ѡPEͷ
	pNewBuffer = pNewBuffer + FileHeader->SizeOfOptionalHeader;	//ƫ�Ƶ��ڱ�
	pSectionHeader = (PIMAGE_SECTION_HEADER)pNewBuffer;			//��ȡ�ڱ�
	//�жϽڱ�ռ��Ƿ����
	if (OptionalHeader->SizeOfHeaders - (DWORD)(&(pSectionHeader[FileHeader->NumberOfSections]) - (DWORD)(NewBuffer)) < 0x50)
	{
		PromoteHeaders();	//�ڱ�ռ䲻��,��������ͷ+�ڱ�
	}
	//ƫ�Ƶ�Ҫ��ӽڱ��λ��
	pNewBuffer = (PBYTE)(&pSectionHeader[FileHeader->NumberOfSections]);
	//�������һ��ȫ0�ṹ
	memset(pNewBuffer + 0x28, 0x0, 0x28);
	//���ýڱ�����
	for (int i = 0; i < strlen((char*)NewSectionName); i++)	//���ýڱ�����
		((PBYTE)((PIMAGE_SECTION_HEADER)pNewBuffer)->Name)[i] = NewSectionName[i];
	((PBYTE)((PIMAGE_SECTION_HEADER)pNewBuffer)->Name)[strlen((char*)NewSectionName)] = 0x0;
	((PIMAGE_SECTION_HEADER)pNewBuffer)->Misc.VirtualSize = Align(SectionSize, OptionalHeader->SectionAlignment);	//�����ڴ��д�С
	DWORD MaxSize = pSectionHeader[FileHeader->NumberOfSections - 1].SizeOfRawData > pSectionHeader[FileHeader->NumberOfSections - 1].Misc.VirtualSize ?
		pSectionHeader[FileHeader->NumberOfSections - 1].SizeOfRawData : pSectionHeader[FileHeader->NumberOfSections - 1].Misc.VirtualSize;
	DWORD SizeOfData = Align(MaxSize, OptionalHeader->SectionAlignment);
	((PIMAGE_SECTION_HEADER)pNewBuffer)->VirtualAddress = pSectionHeader[FileHeader->NumberOfSections - 1].VirtualAddress + SizeOfData;	//�����ڴ���ƫ��
	((PIMAGE_SECTION_HEADER)pNewBuffer)->SizeOfRawData = Align(SectionSize, OptionalHeader->FileAlignment);	//�����ļ��д�С
	((PIMAGE_SECTION_HEADER)pNewBuffer)->PointerToRawData = pSectionHeader[FileHeader->NumberOfSections - 1].PointerToRawData + pSectionHeader[FileHeader->NumberOfSections - 1].SizeOfRawData;	//�����ļ���ƫ��
	for (int i = 0; i < FileHeader->NumberOfSections - 1; i++)
	{
		((PIMAGE_SECTION_HEADER)pNewBuffer)->Characteristics = ((PIMAGE_SECTION_HEADER)pNewBuffer)->Characteristics | pSectionHeader[i].Characteristics;	//��������
	}
	//�޸Ľڱ������
	FileHeader->NumberOfSections++;
	//���ýڵ�����
	memset((PBYTE)NewBuffer + pSectionHeader[FileHeader->NumberOfSections - 1].PointerToRawData, 0x7, Align(SectionSize, OptionalHeader->FileAlignment));
	//�޸�SizeOfImage
	OptionalHeader->SizeOfImage = OptionalHeader->SizeOfImage + Align(SectionSize, OptionalHeader->SectionAlignment);
	//����FileBuffer
	FileBuffer = NewBuffer;
	//���سɹ���־
	return TRUE;
}

BOOL PeInstance::AddDataToNewSection(Cbuffer& SrcBuffer, int flag, size_t SrcSize)
{
	switch (flag)
	{
		case 0:
		{
			if (ImageBuffer)
			{
				ImageBuffer.copy_from(SrcBuffer, SrcSize, pSectionHeader[FileHeader->NumberOfSections - 1].PointerToRawData);
			}
			break;
		}
		case 1:
		{
			if (FileBuffer)
			{
				FileBuffer.copy_from(SrcBuffer, SrcSize, pSectionHeader[FileHeader->NumberOfSections - 1].PointerToRawData);
			}
			break;
		}
	}

	return TRUE;
}

BOOL PeInstance::GetDataFromLastSection(Cbuffer& DesBuffer, int flag, size_t DesSize)
{
	switch (flag)
	{
		case 0:
		{
			if ( ImageBuffer )
			{
				memcpy(DesBuffer,
					(PBYTE)((DWORD)ImageBuffer + pSectionHeader[FileHeader_Image->NumberOfSections - 1].VirtualAddress),
					DesSize);
			}
			break;
		}
		case 1:
		{
			if ( FileBuffer )
			{
				memcpy(DesBuffer,
					(PBYTE)((DWORD)FileBuffer + pSectionHeader[FileHeader->NumberOfSections - 1].PointerToRawData),
					DesSize);
			}
			break;
		}
	}

	return TRUE;
}

DWORD PeInstance::GetLastSectionSize(int flag)
{
	switch (flag)
	{
		case 0:
			return pSectionHeader[FileHeader->NumberOfSections - 1].Misc.VirtualSize;
		case 1:
			return pSectionHeader[FileHeader->NumberOfSections - 1].SizeOfRawData;
	}
	
}

BOOL PeInstance::HaveRelocation(int flag)
{
	switch (flag)
	{
		case 0:
		{
			PIMAGE_DATA_DIRECTORY DataDirectory = OptionalHeader_Image->DataDirectory;
			return (DataDirectory[5].VirtualAddress)
				&& (DataDirectory[5].Size);
		}
		case 1:
		{
			PIMAGE_DATA_DIRECTORY DataDirectory = OptionalHeader->DataDirectory;
			return (DataDirectory[5].VirtualAddress)
				&& (DataDirectory[5].Size);
		}
	}
}

BOOL PeInstance::FixRelocation(DWORD newImageBase, int flag)
{
	PBYTE pTemp = NULL;		//��������ƫ�Ƶ�ָ��
	PDWORD Offset = NULL;	//Ҫ�����ĵ�ַ
	DWORD BeforeBase = 0;
	if (flag)
	{
		BeforeBase = OptionalHeader->ImageBase;	//�����޸�ǰ��ImageBase
		//�޸�ImageBase
		OptionalHeader->ImageBase = newImageBase;
		//��ȡ�ض�λ��ָ��
		PIMAGE_BASE_RELOCATION pBaseRelocation = (PIMAGE_BASE_RELOCATION)(RvaToFoa(OptionalHeader->DataDirectory[5].VirtualAddress) + (DWORD)FileBuffer);
		pTemp = (PBYTE)pBaseRelocation;
		//�����ض�λ��
		for (int i = 0; ((PIMAGE_BASE_RELOCATION)pTemp)->SizeOfBlock != 0 && ((PIMAGE_BASE_RELOCATION)pTemp)->VirtualAddress != 0; i++)
		{
			for (int j = 0; j < (((PIMAGE_BASE_RELOCATION)pTemp)->SizeOfBlock - 8) / 2; j++)
			{
				if ((((PWORD)(pTemp + 0x8))[j] >> 0xC) == 0x3)
				{
					Offset = (PDWORD)((DWORD)FileBuffer + RvaToFoa((((PWORD)(pTemp + 0x8))[j] & 0xFFF) + ((PIMAGE_BASE_RELOCATION)pTemp)->VirtualAddress));
					*Offset = *Offset - BeforeBase + OptionalHeader->ImageBase;
				}
			}
			pTemp = pTemp + ((PIMAGE_BASE_RELOCATION)pTemp)->SizeOfBlock;
		}
	}
	else
	{
		BeforeBase = OptionalHeader_Image->ImageBase;	//�����޸�ǰ��ImageBase
		//�޸�ImageBase
		OptionalHeader_Image->ImageBase = newImageBase;
		//��ȡ�ض�λ��ָ��
		PIMAGE_BASE_RELOCATION pBaseRelocation = (PIMAGE_BASE_RELOCATION)(OptionalHeader->DataDirectory[5].VirtualAddress + (DWORD)ImageBuffer);
		pTemp = (PBYTE)pBaseRelocation;
		//�����ض�λ��
		for (int i = 0; ((PIMAGE_BASE_RELOCATION)pTemp)->SizeOfBlock != 0 && ((PIMAGE_BASE_RELOCATION)pTemp)->VirtualAddress != 0; i++)
		{
			for (int j = 0; j < (((PIMAGE_BASE_RELOCATION)pTemp)->SizeOfBlock - 8) / 2; j++)
			{
				if ((((PWORD)(pTemp + 0x8))[j] >> 0xC) == 0x3)
				{
					Offset = (PDWORD)((DWORD)ImageBuffer + (((PWORD)(pTemp + 0x8))[j] & 0xFFF) + ((PIMAGE_BASE_RELOCATION)pTemp)->VirtualAddress);
					*Offset = *Offset - BeforeBase + OptionalHeader_Image->ImageBase;
				}
			}
			pTemp = pTemp + ((PIMAGE_BASE_RELOCATION)pTemp)->SizeOfBlock;
		}
	}
	
	//���سɹ���ʾ
	return TRUE;
}

BOOL PeInstance::Save(PATH path, int flag)
{
	Cfile NewFile(path);
	switch (flag)
	{
		case 0:
		{
			//����FileBuffer
			NewFile << FileBuffer;
			printf("FileBuffer����ɹ���\n");
			break;
		}
		case 1:
		{
			//����ImageBuffer
			NewFile << ImageBuffer;
			printf("ImageBuffer����ɹ���\n");
			break;
		}
	}

	return TRUE;
}

size_t PeInstance::GetSize()
{
	return FileSize;
}

Cbuffer& PeInstance::GetBufferInstance(int flag)
{
	switch (flag)
	{
		case 0:
		{
			return FileBuffer;
			break;
		}
		case 1:
		{
			return ImageBuffer;
			break;
		}
	}
}

BOOL PeInstance::FixIAT()
{
	//��ȡ�����ָ��
	PIMAGE_IMPORT_DESCRIPTOR pImportDesriptor = (PIMAGE_IMPORT_DESCRIPTOR)(OptionalHeader_Image->DataDirectory[1].VirtualAddress + (DWORD)ImageBuffer);
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
		//printf("***********************��ǰDLL�����֣�%s****************************\n", (PBYTE)(pTemp->Name + (DWORD)ImageBuffer));
		HMODULE hDLL = LoadLibrary((LPCSTR)(pTemp->Name + (DWORD)ImageBuffer));
		for (int k = 0;; k++)
		{
			if (((PDWORD)(pTemp->FirstThunk + (DWORD)ImageBuffer))[k] != 0)
			{
				if (!pTemp->TimeDateStamp)	//���ʱ�����0��˵��û�а󶨵����
				{
					if (((PDWORD)(pTemp->FirstThunk + (DWORD)ImageBuffer))[k] >> 0x1F == 1)
					{
						PIMAGE_THUNK_DATA pTempOri = &((PIMAGE_THUNK_DATA)(pTemp->FirstThunk + (DWORD)ImageBuffer))[k];
						pTempOri->u1.Function = (DWORD)GetProcAddress(hDLL,
							(LPCSTR)(((PDWORD)(pTemp->FirstThunk + (DWORD)ImageBuffer))[k] & 0x7FFFFFFF));
					}
					else
					{
						PIMAGE_THUNK_DATA pTempOri = &((PIMAGE_THUNK_DATA)(pTemp->FirstThunk + (DWORD)ImageBuffer))[k];
						pTempOri->u1.Function = (DWORD)GetProcAddress(hDLL,
							((PIMAGE_IMPORT_BY_NAME)(((PDWORD)(pTemp->FirstThunk + (DWORD)ImageBuffer))[k] + (DWORD)ImageBuffer))->Name);
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
		//getchar();
		pTemp++;
	}
	return TRUE;
}

BOOL PeInstance::FixIATByINT()
{
	//��ȡ�����ָ��
	PIMAGE_IMPORT_DESCRIPTOR pImportDesriptor = (PIMAGE_IMPORT_DESCRIPTOR)(OptionalHeader_Image->DataDirectory[1].VirtualAddress + (DWORD)ImageBuffer);
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
		//printf("***********************��ǰDLL�����֣�%s****************************\n", (PBYTE)(pTemp->Name + (DWORD)ImageBuffer));
		HMODULE hDLL = LoadLibrary((LPCSTR)(pTemp->Name + (DWORD)ImageBuffer));
		for (int k = 0;; k++)
		{
			if (((PDWORD)(pTemp->OriginalFirstThunk + (DWORD)ImageBuffer))[k] != 0)
			{
				if (!pTemp->TimeDateStamp)	//���ʱ�����0��˵��û�а󶨵����
				{
					if (((PDWORD)(pTemp->OriginalFirstThunk + (DWORD)ImageBuffer))[k] >> 0x1F == 1)
					{
						PIMAGE_THUNK_DATA pTempOri = &((PIMAGE_THUNK_DATA)(pTemp->FirstThunk + (DWORD)ImageBuffer))[k];
						pTempOri->u1.Function = (DWORD)GetProcAddress(hDLL,
							(LPCSTR)(((PDWORD)(pTemp->OriginalFirstThunk + (DWORD)ImageBuffer))[k] & 0x7FFFFFFF));
					}
					else
					{
						PIMAGE_THUNK_DATA pTempOri = &((PIMAGE_THUNK_DATA)(pTemp->FirstThunk + (DWORD)ImageBuffer))[k];
						pTempOri->u1.Function = (DWORD)GetProcAddress(hDLL,
							((PIMAGE_IMPORT_BY_NAME)(((PDWORD)(pTemp->OriginalFirstThunk + (DWORD)ImageBuffer))[k] + (DWORD)ImageBuffer))->Name);
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
		//getchar();
		pTemp++;
	}
	return TRUE;
}

int PeInstance::Align(int Value, int align)
{
	{
		if (Value % align == 0)
		{
			return Value;
		}
		return ((Value / align) + 1) * align;
	}
}

DWORD PeInstance::RvaToFoa(DWORD dwRva)
{
	DWORD dwFoa = 0;
	//�ж��Ƿ���ͷ+�ڱ���
	if (dwRva <= OptionalHeader->SizeOfHeaders)
	{
		dwFoa = dwRva;
		return dwFoa;
	}
	//�ж����Ƿ��ڽ���
	int i;
	for (i = 0; i < FileHeader->NumberOfSections; i++)
	{
		if (dwRva >= pSectionHeader[i].VirtualAddress && dwRva <= (pSectionHeader[i].VirtualAddress + pSectionHeader[i].SizeOfRawData))
		{
			dwFoa = dwRva - pSectionHeader[i].VirtualAddress;
			return dwFoa + pSectionHeader[i].PointerToRawData;
		}
	}
}

DWORD PeInstance::FoaToRva(DWORD dwFoa)
{
	DWORD dwRva = 0;

	//�ж��Ƿ���ͷ+�ڱ���
	if (dwFoa <= OptionalHeader->SizeOfHeaders)
	{
		dwRva = dwFoa;
		return dwRva;
	}

	//�ж��Ƿ��ڽ���
	int i = 0;
	for (i = 0; i < FileHeader->NumberOfSections; i++)
	{
		if (dwFoa >= pSectionHeader[i].PointerToRawData && dwFoa <= (pSectionHeader[i].PointerToRawData + pSectionHeader[i].SizeOfRawData))
		{
			dwRva = dwFoa - pSectionHeader[i].PointerToRawData;
			return dwRva + pSectionHeader[i].VirtualAddress;
		}
	}
}

BOOL PeInstance::PromoteHeaders()
{
	PBYTE pTemp = NewBuffer;
	PBYTE pFileBuffer = NewBuffer;
	DWORD SizeOfCopy = (DWORD)(&pSectionHeader[FileHeader->NumberOfSections]) - (DWORD)(pFileBuffer + DosHeader->e_lfanew);
	DWORD FillSize = (DWORD)(&pSectionHeader[FileHeader->NumberOfSections]) - (DWORD)pFileBuffer - 0x40 - SizeOfCopy;
	//��������ͷ+�ڱ�
	for (DWORD i = 0; i < SizeOfCopy; i++)
	{
		(pFileBuffer + 0x40)[i] = (pFileBuffer + DosHeader->e_lfanew)[i];
	}
	//���
	memset((pFileBuffer + 0x40 + SizeOfCopy), 0x0, FillSize);
	//����e_lfanew
	DosHeader->e_lfanew = 0x40;
	//������������ͷ+�ڱ�ָ��
	pTemp = pTemp + DosHeader->e_lfanew;						//ƫ�Ƶ�NTͷ
	NtHeader = (PIMAGE_NT_HEADERS)pTemp;						//��ȡNTͷ
	pTemp = pTemp + 0x4;										//ƫ�Ƶ���׼PEͷ
	FileHeader = (PIMAGE_FILE_HEADER)pTemp;						//��ȡ��׼PEͷ
	pTemp = pTemp + 0x14;										//ƫ�Ƶ���ѡPEͷ
	OptionalHeader = (PIMAGE_OPTIONAL_HEADER)pTemp;				//��ȡ��ѡPEͷ
	pTemp = pTemp + FileHeader->SizeOfOptionalHeader;			//ƫ�Ƶ��ڱ�
	pSectionHeader = (PIMAGE_SECTION_HEADER)pTemp;				//��ȡ�ڱ�
	return TRUE;
}