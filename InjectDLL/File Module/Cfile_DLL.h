#include<windows.h>
#include<string>
#include "../Memory/Cbuffer_operator.h"
#pragma once

//file operator
class Cfile : public Cbuffer_operator {
public:

	//open 
	Cfile(std::string path);

	//open only read
	Cfile(std::string path, int flag);

	//file size
	unsigned size() const;

	//read
	bool operator >> (Cbuffer& buffer);

	//write
	bool operator << (const Cbuffer& buffer);
	 
	//move file pointer
	void move_file_pointer(unsigned dis);

	//close
	~Cfile();

private:

	HANDLE hfile;
};