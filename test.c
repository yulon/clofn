#include <stdio.h>
#include "boox.h"

void foo(void) {
	booxDataDecl(size_t, data);
	printf("I'm foo, %u\n", data);
}

int main(void) {
	foo();
	void (*f)(void) = booxMakeFunc(foo, (void *)2333);
	if (f) {
		f();
	}
}
