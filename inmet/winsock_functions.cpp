#include "main.h"
/*
Steps are as follows:
1- Initialize winsock
2- Create a client socket: a. Declare addrinfo object. b. getaddrinfo() c. create socket object d. socket()
*/

SOCKET get_socket(char* IP, char* iPort)  // MSDN http://msdn.microsoft.com/en-us/library/windows/desktop/ms737591(v=vs.85).aspx
{
	WSADATA wsaData;
	SOCKET ConnectSocket = INVALID_SOCKET;

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
	hints.ai_family = AF_UNSPEC;		// fill the hints structure 
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	iResult = getaddrinfo(IP, iPort, &hints, &result);
	if ( iResult != 0 ) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return INVALID_SOCKET;
	}

	// Create a SOCKET for connecting to server
	ConnectSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (ConnectSocket == INVALID_SOCKET) {
		printf("socket failed with error: %ld\n", WSAGetLastError());
		WSACleanup();
		return INVALID_SOCKET;
	}

	// Connect to handler
	iResult = connect( ConnectSocket, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		closesocket(ConnectSocket);
		return INVALID_SOCKET;
	}
	return ConnectSocket;
}
