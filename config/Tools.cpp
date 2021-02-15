#include "tools.hpp"



BOOL cfg_help::SetRegistryKey(const char* keyPath, const char* keyName, char* keyData)
{
	HKEY  key;
	long  error;
	DWORD disposition;

	error = RegCreateKeyExA(
		HKEY_CURRENT_USER, keyPath, 0, NULL, REG_OPTION_NON_VOLATILE,
		KEY_ALL_ACCESS, NULL, &key, &disposition
	);
	if (error) return FALSE;

	error = RegSetValueExA(
		key, keyName, 0, REG_SZ, (BYTE*)keyData, lstrlen(keyData) + 1
	);
	RegCloseKey(key);
	if (error) return FALSE;

	return TRUE;
}

BOOL cfg_help::GetRegistryKey(const char* keyPath, const char* keyName, char* keyData)
{
	HKEY  key;
	long  error;
	char  content[1024];
	DWORD type = REG_SZ;
	DWORD size = 1024;

	error = RegOpenKeyExA(
		HKEY_CURRENT_USER, keyPath, 0, KEY_ALL_ACCESS, &key
	);
	if (error) return FALSE;

	error = RegQueryValueExA(
		key, keyName, NULL, &type, (BYTE*)content, &size
	);
	RegCloseKey(key);
	if (error) return FALSE;

	lstrcpy(keyData, content);
	return TRUE;
}

