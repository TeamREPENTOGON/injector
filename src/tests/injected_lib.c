#include <Windows.h>

extern int a;

__declspec(dllexport) int entry_point(void* data) {
	struct dummy {
		int a, b;
	}; 
	struct dummy* value = (struct dummy*)data;
	void (*fn)(int, int) = (void(*)(int, int))GetProcAddress(GetModuleHandle(NULL), "set_a");
	fn(value->a, value->b);
	return 0;
}