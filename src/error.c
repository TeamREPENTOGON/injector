#include "injector/error.h"
#include "injector/private/error.h"

__declspec(thread) static int last_error = 0xFFFFFFFF;
__declspec(thread) static const char* last_win32_fn = "";

void injector_set_win32_fn(const char* fn) {
	last_win32_fn = fn;
}

void injector_set_last_error(int error) {
	last_error = error;
}

int injector_error() {
	return last_error;
}

const char* injector_win32_fn() {
	return last_win32_fn;
}

const char* injector_strerror(int error) {
	switch (error) {
	case INJECT_RESULT_OK:
		return "success";

	case INJECT_RESULT_LAST_ERROR:
		return "Win32 error";

	case INJECT_RESULT_INVAL:
		return "invalid parameter";

	case INJECT_RESULT_NO_EXIST:
		return "file does not exist";

	case INJECT_RESULT_NO_DIR:
		return "folder does not exist";

	case INJECT_RESULT_NO_MEM:
		return "out-of-memory";

	case INJECT_RESULT_DIR_NO_DELIM:
		return "path lacks a separator";

	case INJECT_RESULT_STEAM_APPID:
		return "cannot open steam_appid.txt";

	case INJECT_RESULT_NO_SECTION:
		return "section not found";

	default:
		return "unknown error";
	}

	return "impossible state";
}