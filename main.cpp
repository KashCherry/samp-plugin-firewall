#include "main.h"


scalehook_t *scalehook;
chrono::steady_clock::time_point last_update;

typedef pair<string, int> packet;
map<string, int> packetsLog;

map<string, int> bannedIPs;

bool memory_compare(const BYTE *data, const BYTE *pattern, const char *mask)
{
	for (; *mask; ++mask, ++data, ++pattern)
	{
		if (*mask == 'x' && *data != *pattern)
			return false;
	}
	return (*mask) == NULL;
}

DWORD FindPattern(const char *pattern, const char *mask)
{
	DWORD i;
	DWORD size;
	DWORD address;
#ifdef _WIN32
	MODULEINFO info = { 0 };

	address = (DWORD)GetModuleHandle(NULL);
	GetModuleInformation(GetCurrentProcess(), GetModuleHandle(NULL), &info, sizeof(MODULEINFO));
	size = (DWORD)info.SizeOfImage;
#else
	address = 0x804b480; // around the elf base
	size = 0x8128B80 - address;
#endif
	for (i = 0; i < size; ++i)
	{
		if (memory_compare((BYTE *)(address + i), (BYTE *)pattern, mask))
			return (DWORD)(address + i);
	}
	return 0;
}

void BanIP(const char *host)
{
	char Regla[255];
#ifdef _WIN32
	sprintf(Regla, "netsh advfirewall firewall add rule name=\"SA-MP Ban - %s\" dir=in action=block remoteip=%s enable=yes", host, host);
#else
	sprintf(Regla, "iptables -A INPUT -s %s -j DROP", host);
#endif
	system(Regla);
}


int OnSAMPQuery(struct in_addr in, u_short host, char *buffer, int len, SOCKET s)
{
	scalehook_uninstall(scalehook);

	if(bannedIPs.find(inet_ntoa(in)) != bannedIPs.end()) // for prevent add multiple rules
	{
		return 0;
	}

	map<string, int>::iterator iter = packetsLog.find(inet_ntoa(in));
	if(iter == packetsLog.end())
	{
		packetsLog.insert(packet(inet_ntoa(in), 1));
	}
	else
	{
		if(iter->second >= 350)
		{
			logprintf("[FIREWALL] %s was banned - reason: query flood", iter->first.c_str());
			bannedIPs.insert(packet(iter->first.c_str(), iter->second));
			BanIP(iter->first.c_str());
		}	
		iter->second++;
	}

	int result = ((onsampquery_t)scalehook->original_address)(in, host, buffer, len, s);
	scalehook_install(scalehook);
	return result;
}

PLUGIN_EXPORT unsigned int PLUGIN_CALL Supports()
{
    return SUPPORTS_VERSION | SUPPORTS_AMX_NATIVES;
}


PLUGIN_EXPORT bool PLUGIN_CALL Load(void **ppData)
{
	pAMXFunctions = ppData[PLUGIN_DATA_AMX_EXPORTS];
	logprintf = (logprintf_t)ppData[PLUGIN_DATA_LOGPRINTF];
	
	DWORD address = FindPattern(pattern, mask);
	if (!address)
	{
		logprintf(" - Unsupported SA-MP version.");
		return false;
	}

	scalehook = scalehook_create((void*)address, (void*)OnSAMPQuery, 5, scalehook_opcode_jmp);
	if (!scalehook)
	{
		logprintf(" - Hook failed.");
		return false;
	}
	
	logprintf("  - Anti Query flood by Josstaa 1.1 loaded \n");
    return true;
}


PLUGIN_EXPORT void PLUGIN_CALL Unload()
{
	scalehook_uninstall(scalehook);
	scalehook_destroy(scalehook);
    logprintf("  - Anti Query flood by Josstaa 1.1 unloaded");
}

PLUGIN_EXPORT int PLUGIN_CALL AmxLoad( AMX *amx )
{
	return AMX_ERR_NONE;
}


PLUGIN_EXPORT int PLUGIN_CALL AmxUnload( AMX *amx )
{
    return AMX_ERR_NONE;
}

PLUGIN_EXPORT void PLUGIN_CALL ProcessTick()
{
	if (chrono::duration_cast<chrono::milliseconds>(chrono::steady_clock::now() - last_update).count() >= 6000)
	{
		packetsLog.clear();
		bannedIPs.clear();
		last_update = chrono::steady_clock::now();
	}
}