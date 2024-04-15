#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <MinHook.h>

#include <string>
#include <iostream>

unsigned int FindPattern(char *module, const char *funcname, const char *pattern, const char *mask);

namespace types
{
  class Application;
  typedef char(__fastcall *t_Application__init)(Application *_this, int progress);
}

types::t_Application__init Application__init;
types::t_Application__init Application__init_o;

char __fastcall Application__init_hook(types::Application *_this, int progress)
{
  char ret = Application__init_o(_this, progress);

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
      (char *)"payday_win32_release.exe", "",
      "\x6A\x00\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x64\x89\x25\x00\x00\x00\x00\x81\xEC\x00\x00\x00\x00\x53\x55\x56\x57\x68\x00\x00\x00\x00\x33\xDB",
      "x?x????xx????xxxx????xx????xxxxx????xx");

  MH_CreateHook((LPVOID)Application__init, &Application__init_hook, reinterpret_cast<LPVOID *>(&Application__init_o));
  MH_EnableHook((LPVOID)Application__init);
}

BOOL APIENTRY DllMain(HMODULE hmodule, DWORD reason, LPVOID reserved)
{
  if (reason == DLL_PROCESS_ATTACH)
  {
    setup_debugger();
  }
  else if (reason == DLL_PROCESS_DETACH)
  {
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
unsigned int FindPattern(char* module, const char* funcname, const char* pattern, const char* mask)
{
  MODULEINFO mInfo = GetModuleInfo(module);
  DWORD base = (DWORD)mInfo.lpBaseOfDll;
  DWORD size = (DWORD)mInfo.SizeOfImage;
  DWORD patternLength = (DWORD)strlen(mask);
  for (DWORD i = 0; i < size - patternLength; i++)
  {
    bool found = true;
    for (DWORD j = 0; j < patternLength; j++)
    {
      found &= mask[j] == '?' || pattern[j] == *(char*)(base + i + j);
    }
    if (found)
    {
      return base + i;
    }
  }
  return NULL;
}