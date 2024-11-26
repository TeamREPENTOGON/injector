#include <stdio.h>

int a = 12;

__declspec(dllexport) void set_a(int value1, int value2) {
	a = value1 + value2;
}

int main() {
	printf("a = %d\n", a);
	return 0;
}