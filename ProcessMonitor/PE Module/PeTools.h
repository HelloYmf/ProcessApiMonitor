#pragma once
#include <Windows.h>
#include <string>
#include <stdio.h>
#include "../File Module/Cfile.h"
#include "../Memory Module/Cbuffer.h"
#define PATH string
using namespace std;

/*
	PE文件类
*/

class PeInstance
{
public:
	/*
	*	根据缓冲区首地址初始化PE对象,根据flag的不同会把它当作不同的PE对象来处理
	*	flag == 0:当成一个拉伸后的pe文件来处理(无需指定fileSize)
	*	flag == 1:当成是普通的pe文件来处理(需要提供fileSize)
	*/
	PeInstance(HANDLE PeAddr, int flag, size_t fileSize = 0);
	/*
	*	根据指定文件路径初始化PE对象,根据flag的不同会把它当作不同的PE对象来处理
	*	flag == 0:当成一个拉伸后的pe文件来处理
	*	flag == 1:当成是普通的pe文件来处理
	*/
	PeInstance(PATH path,int flag);
	/*
	*	把FileBuffer内容拉伸成内存镜像，由ImageBuffer保存
	*/
	BOOL ToImageBuffer();
	/*
	*	新增节(Fly)
	*	不会产生新的缓冲区,还使用FileBuffer
	*/
	BOOL AddSeaction(size_t SectionSize);
	/*
	*	向最后一个节中添加数据(一般为新增节)
	*	flag == 0:ImageBuffer
	*	flag == 1:FileBuffer
	*/
	BOOL AddDataToNewSection(Cbuffer& SrcBuffer, int flag, size_t SrcSize);
	/*
	*	从最后一个节中取数据(一般为新增节)
	*	flag == 0:ImageBuffer
	*	flag == 1:FileBuffer
	*/
	BOOL GetDataFromLastSection(Cbuffer& DesBuffer, int flag, size_t DesSize);
	/*
	*	获取最后一个节的大小
	*	flag == 0:ImageBuffer
	*	flag == 1:FileBuffer
	*/ 
	DWORD GetLastSectionSize(int flag);
	/*
	*	是否含有重定位表
	*	flag == 0:ImageBuffer
	*	flag == 1:FileBuffer
	*/
	BOOL HaveRelocation(int flag);
	/*
	*	修复重定位表
	*	只支持在FileBuffer的PE文件
	*	可以先在FileBuffer中修复完成再拉伸到内存镜像
	*	flag == 0:ImageBuffer
	*	flag == 1:FileBuffer
	*/ 
	BOOL FixRelocation(DWORD NewBaseAddr, int flag);
	/*
	*	存盘
	*	flag == 0:ImageBuffer
	*	flag == 1:FileBuffer
	*/ 
	BOOL Save(PATH path, int flag);
	/*
	*	获取PE文件大小
	*/ 
	size_t GetSize();
	/*
	*	获取缓冲区首地址的引用
	*	flag == 0:ImageBuffer
	*	flag == 1:FileBuffer
	*/
	Cbuffer& GetBufferInstance(int flag);
	/*
	*	修复IAT表
	*	只支持修复内存镜像中的IAT指向的地址
	*/
	BOOL FixIAT();
	/*
	*	修复IAT表
	*	根据INT表修复
	*/
	BOOL FixIATByINT();
private:
	//获取根据给定值对齐后的值
	int Align(int Value, int align);
	//RVA->FOA
	DWORD RvaToFoa(DWORD dwRva);
	//FOA->RVA
	DWORD FoaToRva(DWORD dwFoa);
	//提升头+节表(在空白区不足以添加一个节表项时)
	BOOL PromoteHeaders();
public:
	//普通PE指针
	PIMAGE_DOS_HEADER DosHeader = NULL;								//DOS头指针
	PIMAGE_NT_HEADERS NtHeader = NULL;								//NT头指针
	PIMAGE_FILE_HEADER FileHeader = NULL;							//标准PE头指针
	PIMAGE_OPTIONAL_HEADER OptionalHeader = NULL;					//可选PE头指针 
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;					//节表指针
	//_Image指针
	PIMAGE_DOS_HEADER DosHeader_Image = NULL;						//DOS头指针_Image
	PIMAGE_NT_HEADERS NtHeader_Image = NULL;						//NT头指针_Image
	PIMAGE_FILE_HEADER FileHeader_Image = NULL;						//标准PE头指针_Image
	PIMAGE_OPTIONAL_HEADER OptionalHeader_Image = NULL;				//可选PE头指针_Image
	PIMAGE_SECTION_HEADER pSectionHeader_Image = NULL;				//节表指针_Image
public:
	//缓冲区
	Cbuffer FileBuffer;												//文件中
	Cbuffer ImageBuffer;											//拉伸后
	Cbuffer NewBuffer;												//临时缓冲区
	//PE文件大小
	size_t FileSize;
};