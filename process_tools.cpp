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
#ifdef DEBUG
		std::cout << "OpenProcessToken error: " << GetLastError() << std::endl;
#endif

		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL, szPrivName, &token_priv.Privileges[0].Luid))
	{

#ifdef DEBUG
			std::cout << "LookupPrivilegeValue error: " << GetLastError() << std::endl;
#endif
			CloseHandle(hToken);
			return FALSE;
	}

	if (!AdjustTokenPrivileges(hToken, FALSE, &token_priv, sizeof(token_priv), NULL, NULL))
	{

#ifdef DEBUG
		std::cout << "AdjustTokenPrivileges error: " << GetLastError() << std::endl;
#endif

		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);
	return TRUE;
}

DWORD get_pid_from_name(IN const char * pProcName)
{
	HANDLE snapshot_proc = cCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot_proc == INVALID_HANDLE_VALUE)
	{

#ifdef DEBUG
		std::cout << "CreateToolhelp32Snapshot error: " << GetLastError() << std::endl;
#endif

		return 0;
	}


	PROCESSENTRY32 ProcessEntry;
	THREADENTRY32 ThreadEntry;
	DWORD pid;
	ProcessEntry.dwSize = sizeof(ProcessEntry);


	if (Process32First(snapshot_proc, &ProcessEntry))
	{
		while (Process32Next(snapshot_proc, &ProcessEntry))
		{
			if (!stricmp(ProcessEntry.szExeFile, pProcName))
			{
				pid = ProcessEntry.th32ProcessID;

				cCloseHandle(snapshot_proc);
				return pid;
			}
		}
	}

	cCloseHandle(snapshot_proc);
	return 0;
}

HANDLE get_process(IN DWORD pid, DWORD access)
{
	HANDLE hProcess = cOpenProcess(access, FALSE, pid);

	if (!hProcess)
	{

#ifdef DEBUG
		std::cout << "OpenProcess error: " << GetLastError() << std::endl;
#endif
		return FALSE;
	}

	return hProcess;
}

BOOL set_proc_critical(HANDLE hProc)
    {

    ULONG count = 1;
    if (NT_SUCCESS(cNtSetInformationProcess(hProc,
							ProcessBreakOnTermination,		// ThreadBreakOnTermination структуре PROCESSINFOCLASS
    						&count,
    						sizeof(ULONG))))
			return TRUE;


#ifdef DEBUG
	std::cout << "NtSetInformationProcess error: " << GetLastError() << std::endl;
#endif
			return FALSE;

    }