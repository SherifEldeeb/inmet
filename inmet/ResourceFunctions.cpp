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
	if (hResInfo == NULL) return -1;

	hRes = LoadResource(NULL, hResInfo);
	if (hRes == NULL) return -1;
	
	tempByteCount = SizeofResource(NULL,hResInfo); // Get the resource size in bytes
	tempBuffer = LockResource(hRes); //pointer to the data

	*buffer = (unsigned char*)VirtualAlloc(0, tempByteCount+1, MEM_COMMIT, PAGE_EXECUTE_READWRITE); //allocate memory, make it executable
	memcpy_s(*buffer,tempByteCount,tempBuffer,tempByteCount); //copy stuff to buffer
	
	FreeResource(hRes);
	return tempByteCount;
}
