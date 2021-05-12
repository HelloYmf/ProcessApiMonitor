#pragma once
#include <Windows.h>
#include <string>
#include <stdio.h>
#include "../File Module/Cfile.h"
#include "../Memory Module/Cbuffer.h"
#define PATH string
using namespace std;

/*
	PE�ļ���
*/

class PeInstance
{
public:
	/*
	*	���ݻ������׵�ַ��ʼ��PE����,����flag�Ĳ�ͬ�����������ͬ��PE����������
	*	flag == 0:����һ��������pe�ļ�������(����ָ��fileSize)
	*	flag == 1:��������ͨ��pe�ļ�������(��Ҫ�ṩfileSize)
	*/
	PeInstance(HANDLE PeAddr, int flag, size_t fileSize = 0);
	/*
	*	����ָ���ļ�·����ʼ��PE����,����flag�Ĳ�ͬ�����������ͬ��PE����������
	*	flag == 0:����һ��������pe�ļ�������
	*	flag == 1:��������ͨ��pe�ļ�������
	*/
	PeInstance(PATH path,int flag);
	/*
	*	��FileBuffer����������ڴ澵����ImageBuffer����
	*/
	BOOL ToImageBuffer();
	/*
	*	������(Fly)
	*	��������µĻ�����,��ʹ��FileBuffer
	*/
	BOOL AddSeaction(size_t SectionSize);
	/*
	*	�����һ�������������(һ��Ϊ������)
	*	flag == 0:ImageBuffer
	*	flag == 1:FileBuffer
	*/
	BOOL AddDataToNewSection(Cbuffer& SrcBuffer, int flag, size_t SrcSize);
	/*
	*	�����һ������ȡ����(һ��Ϊ������)
	*	flag == 0:ImageBuffer
	*	flag == 1:FileBuffer
	*/
	BOOL GetDataFromLastSection(Cbuffer& DesBuffer, int flag, size_t DesSize);
	/*
	*	��ȡ���һ���ڵĴ�С
	*	flag == 0:ImageBuffer
	*	flag == 1:FileBuffer
	*/ 
	DWORD GetLastSectionSize(int flag);
	/*
	*	�Ƿ����ض�λ��
	*	flag == 0:ImageBuffer
	*	flag == 1:FileBuffer
	*/
	BOOL HaveRelocation(int flag);
	/*
	*	�޸��ض�λ��
	*	ֻ֧����FileBuffer��PE�ļ�
	*	��������FileBuffer���޸���������쵽�ڴ澵��
	*	flag == 0:ImageBuffer
	*	flag == 1:FileBuffer
	*/ 
	BOOL FixRelocation(DWORD NewBaseAddr, int flag);
	/*
	*	����
	*	flag == 0:ImageBuffer
	*	flag == 1:FileBuffer
	*/ 
	BOOL Save(PATH path, int flag);
	/*
	*	��ȡPE�ļ���С
	*/ 
	size_t GetSize();
	/*
	*	��ȡ�������׵�ַ������
	*	flag == 0:ImageBuffer
	*	flag == 1:FileBuffer
	*/
	Cbuffer& GetBufferInstance(int flag);
	/*
	*	�޸�IAT��
	*	ֻ֧���޸��ڴ澵���е�IATָ��ĵ�ַ
	*/
	BOOL FixIAT();
	/*
	*	�޸�IAT��
	*	����INT���޸�
	*/
	BOOL FixIATByINT();
private:
	//��ȡ���ݸ���ֵ������ֵ
	int Align(int Value, int align);
	//RVA->FOA
	DWORD RvaToFoa(DWORD dwRva);
	//FOA->RVA
	DWORD FoaToRva(DWORD dwFoa);
	//����ͷ+�ڱ�(�ڿհ������������һ���ڱ���ʱ)
	BOOL PromoteHeaders();
public:
	//��ͨPEָ��
	PIMAGE_DOS_HEADER DosHeader = NULL;								//DOSͷָ��
	PIMAGE_NT_HEADERS NtHeader = NULL;								//NTͷָ��
	PIMAGE_FILE_HEADER FileHeader = NULL;							//��׼PEͷָ��
	PIMAGE_OPTIONAL_HEADER OptionalHeader = NULL;					//��ѡPEͷָ�� 
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;					//�ڱ�ָ��
	//_Imageָ��
	PIMAGE_DOS_HEADER DosHeader_Image = NULL;						//DOSͷָ��_Image
	PIMAGE_NT_HEADERS NtHeader_Image = NULL;						//NTͷָ��_Image
	PIMAGE_FILE_HEADER FileHeader_Image = NULL;						//��׼PEͷָ��_Image
	PIMAGE_OPTIONAL_HEADER OptionalHeader_Image = NULL;				//��ѡPEͷָ��_Image
	PIMAGE_SECTION_HEADER pSectionHeader_Image = NULL;				//�ڱ�ָ��_Image
public:
	//������
	Cbuffer FileBuffer;												//�ļ���
	Cbuffer ImageBuffer;											//�����
	Cbuffer NewBuffer;												//��ʱ������
	//PE�ļ���С
	size_t FileSize;
};