#pragma once

#include <Windows.h>

int injector_inject(const char* executable, const char* cli, int steam_appid,
	const char* loaded_library, const char* entry_point, void* injected_data,
	size_t injected_data_size, HANDLE* thread, HANDLE* process);
