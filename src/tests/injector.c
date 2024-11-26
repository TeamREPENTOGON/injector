#include <stdio.h>
#include <stdlib.h>

#include "injector/error.h"
#include "injector/injector.h"

int main() {
	struct {
		int a, b;
	} value;
	value.a = 12;
	value.b = 13;
	HANDLE process = INVALID_HANDLE_VALUE;
	HANDLE thread = INVALID_HANDLE_VALUE;
	int result = injector_inject("./injected.exe", "", -1, "injected_lib.dll", "entry_point", &value, sizeof(value), &thread, &process);
	if (result) {
		int last_error = injector_error();
		if (last_error == INJECT_RESULT_LAST_ERROR) {
			DWORD error = GetLastError();
			fprintf(stderr, "Error in %s: %d\n", injector_win32_fn(), error);
		} else {
			fprintf(stderr, "Error during injection: %s\n", injector_strerror(last_error));
		}

		return -1;
	}

	WaitForSingleObject(process, INFINITE);
	CloseHandle(process);
	CloseHandle(thread);
	return 0;
}