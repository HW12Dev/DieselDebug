#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <MinHook.h>

#include <string>
#include <iostream>

unsigned __int64 FindPattern(char *module, const char *funcname, const char *pattern, const char *mask);

namespace types
{
  class Application;
  typedef __int64(__fastcall *t_Application__init)(Application *_this, int a2, int a3); // a3 is missing in older versions, always set to 0?
}

types::t_Application__init Application__init;
types::t_Application__init Application__init_o;


__int64 __fastcall Application__init_hook(types::Application *_this, int a2, int a3)
{
  __int64 ret = Application__init_o(_this, a2, a3);

  MessageBox(NULL, "Game is ready to attach a debugger", "", NULL);
  if (!::IsDebuggerPresent())
  {
    ::Sleep(100);
  }
  return ret;
}

void setup_debugger()
{
  MH_Initialize();
  Application__init = (types::t_Application__init)FindPattern(
      (char *)"raid_win64_release.exe", "",
      "\x4C\x89\x44\x24\x00\x48\x89\x54\x24\x00\x48\x89\x4C\x24\x00\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\xAC\x24\x00\x00\x00\x00\x48\x81\xEC\x00\x00\x00\x00\x45\x33\xE4",
      "xxxx?xxxx?xxxx?xxxxxxxxxxxxxxxx????xxx????xxx");

  MH_CreateHook((LPVOID)Application__init, &Application__init_hook, reinterpret_cast<LPVOID *>(&Application__init_o));
  MH_EnableHook((LPVOID)Application__init);
}

BOOL APIENTRY DllMain(HMODULE hmodule, DWORD reason, LPVOID reserved) {
  if(reason == DLL_PROCESS_ATTACH) {
    setup_debugger();
  } else if (reason == DLL_PROCESS_DETACH) {
    MH_Uninitialize();
  }
  return TRUE;
}

#include <psapi.h>

// Signature scanning code is from RAID BLT https://github.com/Luffyyy/Raid-BLT/blob/master/src/signatures/signatures.cpp
//

// https://github.com/Luffyyy/Raid-BLT/blob/master/src/signatures/signatures.cpp#L9
MODULEINFO GetModuleInfo(std::string szModule)
{
  MODULEINFO modinfo = {0};
  HMODULE hModule = GetModuleHandle(szModule.c_str());
  if (hModule == 0)
    return modinfo;
  GetModuleInformation(GetCurrentProcess(), hModule, &modinfo, sizeof(MODULEINFO));
  return modinfo;
}

// https://github.com/Luffyyy/Raid-BLT/blob/master/src/signatures/signatures.cpp#L20
unsigned __int64 FindPattern(char *module, const char *funcname, const char *pattern, const char *mask)
{
  MODULEINFO mInfo = GetModuleInfo(module);
  DWORDLONG base = (DWORDLONG)mInfo.lpBaseOfDll;
  DWORDLONG size = (DWORDLONG)mInfo.SizeOfImage;
  DWORDLONG patternLength = (DWORDLONG)strlen(mask);
  for (DWORDLONG i = 0; i < size - patternLength; i++)
  {
    bool found = true;
    for (DWORDLONG j = 0; j < patternLength; j++)
    {
      found &= mask[j] == '?' || pattern[j] == *(char *)(base + i + j);
    }
    if (found)
    {
      return base + i;
    }
  }
  return NULL;
}