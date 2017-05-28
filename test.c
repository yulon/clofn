#include <stdio.h>
#include "clofn.h"

def_clofn(void, foo, size_t, data, (void), {
	printf("I'm foo, %u\n", data);
})

int main(void) {
	void (*foo)(void) = new_clofn(foo, 2333);
	if (foo) {
		foo();
	}
}
