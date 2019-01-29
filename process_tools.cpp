#include "process_tools.h"

// Set privileges. For example: set_privileges(SE_DEBUG_NAME);
//
BOOL set_privileges(LPCTSTR szPrivName)
{

	TOKEN_PRIVILEGES token_priv = { 0 };
	HANDLE hToken = 0;

	token_priv.PrivilegeCount = 1;
	token_priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
#ifdef _DEBUG
		printf("OpenProcessToken error:  %d.\n", GetLastError());
#endif

		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL, szPrivName, &token_priv.Privileges[0].Luid))
	{

#ifdef _DEBUG
		printf("LookupPrivilegeValue error:  %d.\n", GetLastError());
#endif
		CloseHandle(hToken);
		return FALSE;
	}

	if (!AdjustTokenPrivileges(hToken, FALSE, &token_priv, sizeof(token_priv), NULL, NULL))
	{

#ifdef _DEBUG
		printf("AdjustTokenPrivileges error:  %d.\n", GetLastError());
#endif

		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);
	return TRUE;
}

DWORD get_pid_from_name(IN const char * pProcName)
{
	HANDLE snapshot_proc = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot_proc == INVALID_HANDLE_VALUE)
	{

#ifdef _DEBUG
		printf("CreateToolhelp32Snapshot error:  %d.\n", GetLastError());
#endif

		return 0;
	}


	PROCESSENTRY32 ProcessEntry;
	DWORD pid;
	ProcessEntry.dwSize = sizeof(ProcessEntry);


	if (Process32First(snapshot_proc, &ProcessEntry))
	{
		while (Process32Next(snapshot_proc, &ProcessEntry))
		{
			if (!_stricmp(ProcessEntry.szExeFile, pProcName))
			{
				pid = ProcessEntry.th32ProcessID;

				CloseHandle(snapshot_proc);
				return pid;
			}
		}
	}

	CloseHandle(snapshot_proc);
	return 0;
}

HANDLE get_process(IN DWORD pid, DWORD access)
{
	HANDLE hProcess = OpenProcess(access, FALSE, pid);

	if (!hProcess)
	{

#ifdef _DEBUG
		printf("OpenProcess error:  %d.\n", GetLastError());
#endif
		return FALSE;
	}

	return hProcess;
}

BOOL set_proc_critical(HANDLE hProc)
{

	ULONG ProcessInformation = 1;
	if (NT_SUCCESS(cNtSetInformationProcess(hProc,
		ProcessBreakOnTermination,
		&ProcessInformation,
		sizeof(ULONG))))
		return TRUE;

#ifdef _DEBUG
	printf("NtSetInformationProcess error:  %d.\n", GetLastError());
#endif
	return FALSE;

}

BOOL is_critical(IN HANDLE hProcess)
{
	BOOL critical;

	if (!IsProcessCritical(hProcess, &critical))
	{
#ifdef _DEBUG
		printf("IsProcessCritical error:  %d.\n", GetLastError());
#endif
	}


	return critical;
}