#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include "api/api.h"

BOOL set_privileges(LPCTSTR szPrivName);

BOOL set_proc_critical(HANDLE hProc);

DWORD get_pid_from_name(IN const char * pProcName);

HANDLE get_process(IN DWORD pid, DWORD access);

