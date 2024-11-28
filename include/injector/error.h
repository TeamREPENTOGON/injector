#pragma once

#ifdef __cplusplus
extern "C" {
#endif

enum injector_inject_result {
	INJECT_RESULT_NO_SECTION = -8,
	INJECT_RESULT_STEAM_APPID = -7,
	INJECT_RESULT_DIR_NO_DELIM = -6,
	INJECT_RESULT_NO_MEM = -5,
	INJECT_RESULT_NO_DIR = -4,
	INJECT_RESULT_NO_EXIST = -3,
	INJECT_RESULT_INVAL = -2,
	INJECT_RESULT_LAST_ERROR = -1,
	INJECT_RESULT_OK = 0,
};

int injector_error();
const char* injector_strerror(int error);
const char* injector_win32_fn();

#ifdef __cplusplus
}
#endif