#pragma once

#include <Windows.h>

typedef struct loader_data_s {
	HMODULE(WINAPI *load_library_a)(LPCSTR);
	FARPROC(WINAPI *get_proc_address)(HMODULE, LPCSTR);
	BOOL(WINAPI *free_library)(HMODULE);
	size_t lib_name_len;
	size_t entry_point_len;
	size_t injected_data_len;
	char data[0];
} loader_data_t;

loader_data_t* allocate_loader_data(const char* library_name, const char* entry_point,
	void* data, size_t len);
size_t loader_data_size(loader_data_t const* data);
DWORD (WINAPI *get_loader_function_address())(LPVOID);