#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <WinSock2.h>
#include <Windows.h>
#include <ImageHlp.h>

#include "injector/injector.h"
#include "injector/error.h"
#include "injector/private/error.h"
#include "injector/private/loader.h"

static bool file_exists(const char* path);
static char* get_directory(const char* full_path, char** file_part);
static char* get_full_path(const char* path);
static bool handle_steam_appid(const char* folder, int steam_appid);
static int inject(const char* full_path, const char* cli, const char* folder,
	const char* library_name, const char* entry_point, void* injected_data,
	size_t data_len, LPTHREAD_START_ROUTINE* routine, void** routine_data,
	HANDLE *thread, HANDLE* result);
static char* normalize_cli(const char* full_path, const char* cli);
static IMAGE_SECTION_HEADER* find_section(const char* name);

int injector_inject(const char* executable, const char* cli, int steam_appid,
	const char* loaded_library, const char* entry_point, void* injected_data,
	size_t injected_data_size, HANDLE* process_handle, HANDLE* thread_handle) {
	if (!executable || !process_handle || !thread_handle) {
		return INJECT_RESULT_INVAL;
	}

	int result = -1;
	char* full_path = NULL;
	char* folder = NULL;
	char* file_part = NULL;
	char* command_line = NULL;
	LPTHREAD_START_ROUTINE routine = NULL;
	void* loader_data = NULL;
	HANDLE thread = INVALID_HANDLE_VALUE;
	DWORD wait_result = 0;

	full_path = get_full_path(executable);
	if (!full_path) {
		goto finish;
	}

	if (!file_exists(full_path)) {
		result = INJECT_RESULT_NO_EXIST;
		goto finish;
	}

	command_line = normalize_cli(full_path, cli);
	if (!command_line) {
		goto finish;
	}

	folder = get_directory(full_path, &file_part);
	if (!folder) {
		result = INJECT_RESULT_NO_DIR;
		goto finish;
	}

	if (steam_appid > 0 && !handle_steam_appid(folder, steam_appid)) {
		goto finish;
	}

	if (inject(full_path, command_line, folder, loaded_library, entry_point,
		injected_data, injected_data_size, &routine, &loader_data, thread_handle, 
		process_handle)) {
		goto finish;
	}

	thread = CreateRemoteThread(*process_handle, NULL, 0, routine, loader_data, 0, NULL);
	if (!thread) {
		injector_set_win32_fn("CreateRemoteThread");
		goto finish;
	}

	wait_result = WaitForSingleObject(thread, INFINITE);
	if (wait_result) {
		injector_set_win32_fn("WaitForSingleObject");
		goto finish;
	}

	ResumeThread(*thread_handle);
	result = INJECT_RESULT_OK;

finish:
	if (thread != INVALID_HANDLE_VALUE && thread != NULL) {
		CloseHandle(thread);
	}
	free(folder);
	free(command_line);
	free(full_path);

	return result;
}

bool file_exists(const char* path) {
	WIN32_FIND_DATAA data;
	memset(&data, 0, sizeof(data));

	HANDLE handle = FindFirstFileA(path, &data);
	if (handle == INVALID_HANDLE_VALUE)
		return false;

	CloseHandle(handle);
	return true;
}

char* get_full_path(const char* path) {
	DWORD len = GetFullPathNameA(path, 0, NULL, NULL);
	if (len == 0) {
		injector_set_win32_fn("GetFullPathNameA");
		injector_set_last_error(INJECT_RESULT_LAST_ERROR);
		return NULL;
	}

	char* buffer = malloc(len + 1);
	if (!buffer) {
		injector_set_last_error(INJECT_RESULT_NO_MEM);
		return NULL;
	}

	if (GetFullPathNameA(path, len + 1, buffer, NULL) == 0) {
		injector_set_win32_fn("GetFullPathNameA");
		injector_set_last_error(INJECT_RESULT_LAST_ERROR);
		free(buffer);
		return NULL;
	}

	return buffer;
}

char* get_directory(const char* path, char** file_part) {
	const char* delim = strrchr(path, '\\');
	if (!delim) {
		injector_set_last_error(INJECT_RESULT_DIR_NO_DELIM);
		return NULL;
	}

	char* buffer = malloc(delim - path + 1);
	if (!buffer) {
		injector_set_last_error(INJECT_RESULT_NO_MEM);
		return NULL;
	}

	if (file_part) {
		*file_part = (char*)delim + 1;
	}

	memcpy(buffer, path, delim - path);
	buffer[delim - path] = '\0';
	return buffer;
}

bool handle_steam_appid(const char* folder, int steam_appid) {
	const char* suffix = "/steam_appid.txt";
	char* full_path = malloc(strlen(folder) + strlen(suffix) + 1);
	if (!full_path) {
		injector_set_last_error(INJECT_RESULT_NO_MEM);
		return false;
	}

	strcpy(full_path, folder);
	strcat(full_path, suffix);

	if (!file_exists(full_path)) {
		FILE* file = fopen(full_path, "w");
		if (!file) {
			injector_set_last_error(INJECT_RESULT_STEAM_APPID);
			free(full_path);
			return false;
		}

		fprintf(file, "%d", steam_appid);
		fclose(file);
	}

	free(full_path);
	return true;
}

char* normalize_cli(const char* full_path, const char* cli) {
	if (!cli) {
		char* result = malloc(strlen(full_path) + 1);
		if (!result) {
			injector_set_last_error(INJECT_RESULT_NO_MEM);
			return NULL;
		}

		strcpy(result, full_path);
		return result;
	}

	char* result = malloc(strlen(full_path) + 1 /* space */ + strlen(cli) + 1);
	if (!result) {
		injector_set_last_error(INJECT_RESULT_NO_MEM);
		return NULL;
	}

	strcpy(result, full_path);
	strcat(result, " ");
	strcat(result, cli);
	return result;
}

int inject(const char* full_path, const char* cli, const char* folder,
	const char* library_name, const char* entry_point, void* injected_data,
	size_t data_len, LPTHREAD_START_ROUTINE* routine, void** routine_data,
	HANDLE* thread_handle, HANDLE* process_handle) {
	STARTUPINFOA startup_info;
	PROCESS_INFORMATION process_info;

	memset(&startup_info, 0, sizeof(startup_info));
	memset(&process_info, 0, sizeof(process_info));

	if (!CreateProcessA(full_path, (char*)cli, NULL, NULL, FALSE, CREATE_SUSPENDED,
		NULL, folder, &startup_info, &process_info)) {
		injector_set_win32_fn("CreateProcessA");
		injector_set_last_error(INJECT_RESULT_LAST_ERROR);
		return -1;
	}

	HANDLE process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
		FALSE, process_info.dwProcessId);
	if (process == NULL) {
		injector_set_win32_fn("OpenProcess");
		injector_set_last_error(INJECT_RESULT_LAST_ERROR);
		return -1;
	}

	CloseHandle(process_info.hProcess);

	loader_data_t* loader_data = allocate_loader_data(library_name, entry_point,
		injected_data, data_len);
	int result = -1;
	IMAGE_SECTION_HEADER* headers = NULL;
	HMODULE self = GetModuleHandle(NULL);
	size_t data_size = 0;
	MEMORY_BASIC_INFORMATION info;
	memset(&info, 0, sizeof(info));

	if (!loader_data) {
		injector_set_last_error(INJECT_RESULT_NO_MEM);
		goto finish;
	}

	data_size = loader_data_size(loader_data);

	headers = find_section(".loader");
	if (!headers) {
		injector_set_last_error(INJECT_RESULT_NO_SECTION);
		goto finish;
	}

	void* remote_page = VirtualAllocEx(process, NULL,
		headers->Misc.VirtualSize + data_size,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!remote_page) {
		injector_set_win32_fn("VirtualAllocEx");
		injector_set_last_error(INJECT_RESULT_LAST_ERROR);
		goto finish;
	}

	BOOL ok = WriteProcessMemory(process, remote_page, (char*)self + headers->VirtualAddress, headers->Misc.VirtualSize, NULL);
	if (!ok) {
		injector_set_win32_fn("WriteProcessMemory");
		injector_set_last_error(INJECT_RESULT_LAST_ERROR);
		goto finish;
	}

	ok = WriteProcessMemory(process, (char*)remote_page + headers->Misc.VirtualSize, loader_data, data_size, NULL);
	if (!ok) {
		injector_set_win32_fn("WriteProcessMemory");
		injector_set_last_error(INJECT_RESULT_LAST_ERROR);
		goto finish;
	}

	ok = VirtualQueryEx(process, remote_page, &info, sizeof(info));
	if (!ok) {
		injector_set_win32_fn("VirtualQueryEx");
		injector_set_last_error(INJECT_RESULT_LAST_ERROR);
		goto finish;
	}

	DWORD dummy = 0;
	ok = VirtualProtectEx(process, info.BaseAddress, info.RegionSize, PAGE_EXECUTE_READ, &dummy);
	
	*routine = (LPTHREAD_START_ROUTINE)((char*)remote_page + 
		((DWORD)get_loader_function_address() - ((DWORD)self + headers->VirtualAddress)));
	*routine_data = (char*)remote_page + headers->Misc.VirtualSize;
	*process_handle = process;
	*thread_handle = process_info.hThread;
	result = 0;

finish:
	if (result != 0) {
		if (loader_data) {
			free(loader_data);
		}
		ResumeThread(process);
		CloseHandle(process);
	}

	return result;
}

IMAGE_SECTION_HEADER* find_section(const char* name) {
	PIMAGE_NT_HEADERS nt_headers = ImageNtHeader(GetModuleHandle(NULL));
	IMAGE_SECTION_HEADER* headers = (IMAGE_SECTION_HEADER*)((char*)&nt_headers->OptionalHeader + nt_headers->FileHeader.SizeOfOptionalHeader);

	for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
		if (!strcmp(headers->Name, name)) {
			return headers;
		}

		++headers;
	}

	return NULL;
}