BOOL set_privileges(LPCTSTR szPrivName);

DWORD get_pid_from_name(IN const char * pProcName);

HANDLE get_process(IN DWORD pid, DWORD access);

BOOL set_proc_critical(HANDLE hProc);