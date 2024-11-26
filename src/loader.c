#include "injector/private/loader.h"

#pragma code_seg(push, r1, ".loader")
#pragma check_stack(off)
#pragma runtime_checks("", off)

__declspec(safebuffers) static DWORD WINAPI loader(LPVOID param) {
	loader_data_t* data = (loader_data_t*)param;
	HMODULE module = data->load_library_a(data->data);
	if (module == NULL) {
		return -1;
	}

	int (*proc)(void*) = (int(*)(void*))data->get_proc_address(module, data->data + data->lib_name_len + 1);
	if (!proc) {
		data->free_library(module);
		return -1;
	}

	return proc((char*)data->data + data->lib_name_len + data->entry_point_len + 2);
}

#pragma code_seg(pop, r1)
#pragma check_stack
#pragma runtime_checks("", restore)

DWORD (WINAPI *get_loader_function_address())(LPVOID) {
	return &loader;
}

loader_data_t* allocate_loader_data(const char* library_name, const char* entry_point,
	void* data, size_t len) {
	HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
	if (!kernel32) {
		return NULL;
	}

	size_t lib_name_len = strlen(library_name);
	size_t entry_point_len = strlen(entry_point);
	loader_data_t* loader_data = malloc(sizeof(loader_data_t) + len + lib_name_len + entry_point_len + 2);
	if (!loader_data) {
		return NULL;
	}

	loader_data->free_library = (BOOL(WINAPI*)(HMODULE))GetProcAddress(kernel32, "FreeLibrary");
	loader_data->get_proc_address = (FARPROC(WINAPI*)(HMODULE, LPCSTR))GetProcAddress(kernel32, "GetProcAddress");
	loader_data->load_library_a = (HMODULE(WINAPI*)(LPCSTR))GetProcAddress(kernel32, "LoadLibraryA");
	loader_data->lib_name_len = lib_name_len;
	loader_data->entry_point_len = entry_point_len;
	loader_data->injected_data_len = len;

	char* position = loader_data->data;
	memcpy(position, library_name, lib_name_len + 1);
	position += lib_name_len + 1;
	memcpy(position, entry_point, entry_point_len + 1);
	position += entry_point_len + 1;
	memcpy(position, data, len);

	return loader_data;
}

size_t loader_data_size(loader_data_t const* data) {
	return sizeof(*data) + data->lib_name_len + data->entry_point_len + data->injected_data_len + 2;
}