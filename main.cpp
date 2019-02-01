#include "process_tools.h"

int main(int argc, char **argv)
{
	printf("Set critical process\n");
	printf("Usage: critical.exe <process name>\n");

	if (argc == 2)

		if (is_critical(get_process(get_pid_from_name(argv[1]), PROCESS_ALL_ACCESS)))
		{
			printf("Process is already critical\n");
			return 0;

		}
		else
		{
			if (set_privileges(SE_DEBUG_NAME))
				printf("SE_DEBUG_NAME is granted! \n");

			set_proc_critical(get_process(get_pid_from_name(argv[1]), PROCESS_ALL_ACCESS));
		}

	system("pause");

	return 0;
}
