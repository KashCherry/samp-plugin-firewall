#include "scalehook/scalehook.h"
#ifdef scalehook_windows

	#include <windows.h>
	#include <process.h>
	#include <psapi.h>

	const char *pattern = "\x83\xEC\x24\x53\x55\x56\x57\x8B\x7C\x24\x44\x83\xFF\x04\x0F\x8E\x00\x00\x00\x00";
	const char *mask = "xxxxxxxxxxxxxxxx????";
#else
	const char *pattern = "\x55\x89\xE5\x81\xEC\xA8\x00\x00\x00\x89\x5D\xF4\x8B\x5D\x14\x90\x75\xF8\x8B\x75";
	const char *mask = "xxxxxx???xxxxxxxxxxx";

	typedef int SOCKET;
	typedef unsigned long DWORD;
	typedef unsigned char BYTE;
	typedef BYTE * PBYTE;

	#include <unistd.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
	#include <sys/mman.h>
	#include <string.h>
	
#endif


#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string>
#include <chrono>

#include <math.h>
#include <map>

using namespace std;


#include "SDK/amx/amx.h"
#include "SDK/plugincommon.h"



typedef int(*onsampquery_t)(struct in_addr in,  u_short hostshort, char *data, int len, SOCKET s);

typedef void (*logprintf_t)(char* format, ...);
logprintf_t logprintf;

extern void *pAMXFunctions;


