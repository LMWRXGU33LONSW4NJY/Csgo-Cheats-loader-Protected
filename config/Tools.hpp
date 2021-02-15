#pragma once
#include <iostream>
#include <d3d9.h>
#include <d3dx9.h>
#include <string>
#include <memory>
#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include <strsafe.h>
#include <IPTypes.h>
#include <Shlwapi.h>
#include <Iphlpapi.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <Wbemidl.h>
#include <chrono>
#include <atlstr.h>
#include <winsock.h>
#include <fstream>
#include <ctime>
#include <vector>
#include <random>
#include <thread>
#include <mutex>
#include <filesystem>


class cfg_help
{
public:

	static BOOL SetRegistryKey(const char* keyPath, const char* keyName, char* keyData);
	static BOOL GetRegistryKey(const char* keyPath, const char* keyName, char* keyData);

};


