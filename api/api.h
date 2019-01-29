#include <Windows.h>
#include"undoc.h"

NTSTATUS cNtTerminateProcess(
	IN HANDLE               ProcessHandle OPTIONAL,
	IN NTSTATUS             ExitStatus);

LPVOID WINAPI cLockResource(
	_In_ HGLOBAL hResData
);

HGLOBAL WINAPI cLoadResource(
	_In_opt_ HMODULE hModule,
	_In_     HRSRC   hResInfo
);

HANDLE cCreateToolhelp32Snapshot(DWORD	flags,
	DWORD	pid
);

BOOL cCreateProcessA(__in_opt			LPCSTR					application_name,
	__inout_opt		LPSTR					command_line,
	__in_opt		LPSECURITY_ATTRIBUTES	process_attributes,
	__in_opt		LPSECURITY_ATTRIBUTES	thread_attributes,
	__in			BOOL					inherit_handle,
	__in			DWORD					creation_flags,
	__in_opt		LPVOID					environment,
	__in_opt		LPCSTR					current_directory,
	__in			LPSTARTUPINFOA			startup_info,
	__out			LPPROCESS_INFORMATION	process_info);

HANDLE cOpenThread(__in	DWORD	access,
	__in	BOOL	inherit_handle,
	__in	DWORD	tid);

BOOL cSetThreadContext(__in		HANDLE			thread,
	__in		const PCONTEXT	context);

LPVOID cVirtualAllocEx(__in		HANDLE		process,
	__in_opt		LPVOID		address,
	__in		UINT		size,
	__in		DWORD		alloc_type,
	__in		DWORD		page_security);

BOOL cWriteProcessMemory(__in		HANDLE		process,
	__in		LPVOID		base,
	__in		LPCVOID		buffer,
	__in		UINT		size,
	__out		PUINT		written);

NTSTATUS cNtSetInformationProcess(
	IN HANDLE               ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	IN PVOID                ProcessInformation,
	IN ULONG                ProcessInformationLength);

HANDLE WINAPI cOpenProcess(
	_In_  DWORD dwDesiredAccess,
	_In_  BOOL bInheritHandle,
	_In_  DWORD dwProcessId
);

NTSTATUS
cNtDebugActiveProcess(
	IN HANDLE               ProcessHandle,
	IN HANDLE               DebugObjectHandle);


NTSTATUS
cNtCreateDebugObject(
	OUT PHANDLE             DebugObjectHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
	IN BOOLEAN              KillProcessOnExit);

HRSRC cFindResourceA(
	HMODULE hModule,
	LPCSTR  lpName,
	LPCSTR  lpType
);


HANDLE cCreateFileA(__in		LPCSTR					file_name,
	DWORD					access,
	DWORD					share_mode,
	LPSECURITY_ATTRIBUTES	security,
	DWORD					creation_disposition,
	DWORD					flags,
	HANDLE					template_file);

VOID cRtlInitUnicodeString(
	PUNICODE_STRING DestinationString,
	PCWSTR          SourceString
);

HANDLE cCreateFileTransactedA(
	LPCSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile,
	HANDLE                hTransaction,
	PUSHORT               pusMiniVersion,
	PVOID                 lpExtendedParameter
);

PIMAGE_NT_HEADERS cRtlImageNtHeader(
	_In_ PVOID Base
);

NTSTATUS cRtlDestroyProcessParameters(
	_In_ PRTL_USER_PROCESS_PARAMETERS32 ProcessParameters
);

NTSTATUS cNtFreeVirtualMemory(
	_In_       HANDLE ProcessHandle,
	_Inout_    PVOID *BaseAddress,
	_Inout_    PSIZE_T RegionSize,
	_In_       ULONG FreeType
);

NTSTATUS cNtCreateThreadEx(
	_Out_ PHANDLE hThread,
	_In_  ACCESS_MASK DesiredAccess,
	_In_  LPVOID ObjectAttributes,
	_In_  HANDLE ProcessHandle,
	_In_  LPTHREAD_START_ROUTINE lpStartAddress,
	_In_  LPVOID lpParameter,
	_In_  BOOL CreateSuspended,
	_In_  DWORD StackZeroBits,
	_In_  DWORD SizeOfStackCommit,
	_In_  DWORD SizeOfStackReserve,
	_Out_ LPVOID lpBytesBuffer);

NTSTATUS cNtReadVirtualMemory(
	_In_		HANDLE ProcessHandle,
	_In_opt_	PVOID BaseAddress,
	_Out_		PVOID Buffer,
	_In_		SIZE_T BufferSize,
	_Out_opt_	PSIZE_T NumberOfBytesRead
);

NTSTATUS cNtQueryInformationProcess(
	_In_		HANDLE ProcessHandle,
	_In_		PROCESSINFOCLASS ProcessInformationClass,
	_Out_		PVOID ProcessInformation,
	_In_		ULONG ProcessInformationLength,
	_Out_opt_	PULONG ReturnLength
);

NTSTATUS cNtRollbackTransaction(
	_In_ HANDLE  TransactionHandle,
	_In_ BOOLEAN Wait);

NTSTATUS cNtCreateSection(
	_Out_		PHANDLE SectionHandle,
	_In_		ACCESS_MASK DesiredAccess,
	_In_opt_	POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_	PLARGE_INTEGER MaximumSize,
	_In_		ULONG SectionPageProtection,
	_In_		ULONG AllocationAttributes,
	_In_opt_	HANDLE FileHandle
);

NTSTATUS cNtAllocateVirtualMemory(
	_In_        HANDLE ProcessHandle,
	_Inout_     PVOID *BaseAddress,
	_In_        ULONG_PTR ZeroBits,
	_Inout_     PSIZE_T RegionSize,
	_In_        ULONG AllocationType,
	_In_        ULONG Protect
);

NTSTATUS cNtCreateTransaction(
	_Out_     PHANDLE TransactionHandle,
	_In_      ACCESS_MASK DesiredAccess,
	_In_opt_  POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_  LPGUID Uow,
	_In_opt_  HANDLE TmHandle,
	_In_opt_  ULONG CreateOptions,
	_In_opt_  ULONG IsolationLevel,
	_In_opt_  ULONG IsolationFlags,
	_In_opt_  PLARGE_INTEGER Timeout,
	_In_opt_  PUNICODE_STRING Description
);

NTSTATUS cNtCreateSection(
	_Out_		PHANDLE SectionHandle,
	_In_		ACCESS_MASK DesiredAccess,
	_In_opt_	POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_	PLARGE_INTEGER MaximumSize,
	_In_		ULONG SectionPageProtection,
	_In_		ULONG AllocationAttributes,
	_In_opt_	HANDLE FileHandle
);

NTSTATUS cNtWriteVirtualMemory(
	_In_        HANDLE ProcessHandle,
	_In_opt_    PVOID BaseAddress,
	_In_        VOID *Buffer,
	_In_        SIZE_T BufferSize,
	_Out_opt_   PSIZE_T NumberOfBytesWritten
);

NTSTATUS cNtAllocateVirtualMemory(
	_In_        HANDLE ProcessHandle,
	_Inout_     PVOID *BaseAddress,
	_In_        ULONG_PTR ZeroBits,
	_Inout_     PSIZE_T RegionSize,
	_In_        ULONG AllocationType,
	_In_        ULONG Protect
);

NTSTATUS cRtlCreateProcessParametersEx(
	_Out_	 PRTL_USER_PROCESS_PARAMETERS32 *pProcessParameters,
	_In_	 PUNICODE_STRING ImagePathName,
	_In_opt_ PUNICODE_STRING DllPath,
	_In_opt_ PUNICODE_STRING CurrentDirectory,
	_In_opt_ PUNICODE_STRING CommandLine,
	_In_opt_ PVOID Environment,
	_In_opt_ PUNICODE_STRING WindowTitle,
	_In_opt_ PUNICODE_STRING DesktopInfo,
	_In_opt_ PUNICODE_STRING ShellInfo,
	_In_opt_ PUNICODE_STRING RuntimeData,
	_In_	 ULONG Flags);


NTSTATUS cNtCreateProcessEx(
	_Out_    PHANDLE ProcessHandle,
	_In_     ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_     HANDLE ParentProcess,
	_In_     ULONG Flags,
	_In_opt_ HANDLE SectionHandle,
	_In_opt_ HANDLE DebugPort,
	_In_opt_ HANDLE ExceptionPort,
	_In_ BOOLEAN InJob);



VOID cGetSystemTime(
	__out LPSYSTEMTIME system_time);

VOID cExitProcess(
	__in UINT exit_code);

VOID cSleep(
	__in DWORD time);

BOOL cCreateDirectoryA(
	__in		LPCSTR					path_name,
	__in_opt	LPSECURITY_ATTRIBUTES	security_attributes);

LPVOID cVirtualAlloc(LPVOID		address,
	__in		SIZE_T		size,
	__in		DWORD		alloc_type,
	__in		DWORD		page_security);

DWORD WINAPI cSizeofResource(
	_In_opt_ HMODULE hModule,
	_In_     HRSRC   hResInfo
);

BOOL WINAPI cFreeResource(
	_In_ HGLOBAL hglbResource
);

BOOL cOpenProcessToken(
	HANDLE  ProcessHandle,
	DWORD   DesiredAccess,
	PHANDLE TokenHandle
);

BOOL cAdjustTokenPrivileges(
	HANDLE            TokenHandle,
	BOOL              DisableAllPrivileges,
	PTOKEN_PRIVILEGES NewState,
	DWORD             BufferLength,
	PTOKEN_PRIVILEGES PreviousState,
	PDWORD            ReturnLength
);

BOOL WINAPI cCloseHandle(
	_In_ HANDLE hObject
);

HANDLE cGetCurrentProcess(VOID);

HMODULE cGetModuleHandleW
(
	LPCWSTR module
);

HRSRC cFindResourceW(
	HMODULE hModule,
	LPCWSTR  lpName,
	LPCWSTR  lpType
);

BOOL cLookupPrivilegeValueW(
	LPCWSTR lpSystemName,
	LPCWSTR lpName,
	PLUID  lpLuid
);

BOOL cIsWow64Process(
	HANDLE hProcess,
	PBOOL  Wow64Process
);

