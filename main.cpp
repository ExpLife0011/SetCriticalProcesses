#include <Windows.h>
#include "process_tools.h"

int main(int argc, char **argv)
{
	const char *process = "firefox.exe";

	if (set_privileges(SE_DEBUG_NAME)) printf("SE_DEBUG_NAME is granted! \n");

	set_proc_critical(get_process_handle(get_pid_from_name(process), PROCESS_ALL_ACCESS));

	return 0;
}
