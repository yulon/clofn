#ifndef _CLOFN_H
#define _CLOFN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>

#define CLOFN_PHSIZE_MAX 1024
#define _CLOFN_SCIENCE_NUMBER 0x58ffffbffdffffafULL

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
	#include <sys/mman.h>
	#include <sys/user.h>
	static inline bool _clofn_active_memory(void *ptr, size_t size) {
		return mprotect((void *)(((size_t)ptr >> PAGE_SHIFT) << PAGE_SHIFT), size, PROT_READ | PROT_EXEC | PROT_WRITE) == 0;
	}
#elif defined(_WIN32)
	#include <windows.h>
	static inline bool _clofn_active_memory(void *ptr, size_t size) {
		DWORD old_protect;
		return VirtualProtect(ptr, size, PAGE_EXECUTE_READWRITE, &old_protect);
	}
#else
	#error Clofn: not support this OS!
#endif

#define def_clofn(result_type, name, closure_type /* size equal to machine word */, closure_name, args, body) \
	static result_type _clofn__##name args { \
		volatile closure_type closure_name = (closure_type)_CLOFN_SCIENCE_NUMBER; \
		body \
	} \
	static size_t _clofn__##name##__phsize = 0; \
	static size_t _clofn__##name##__phhash = 0;

static void *_new_clofn(void *prototype, size_t *phsize, void *data) {
	#ifdef CLOFN_PRINT_HEADER
		printf("Clofn: prototype header (%08X) { ", prototype);
	#endif

	size_t offset = *phsize;
	if (!offset) {
		for (; offset < CLOFN_PHSIZE_MAX; offset++) {
			if (*(size_t *)((uintptr_t)prototype + offset) == (size_t)_CLOFN_SCIENCE_NUMBER) {
				if (!*phsize) {
					*phsize = offset;
				}

				#ifdef CLOFN_PRINT_HEADER
					printf("} @%u+%u\n", offset, sizeof(uintptr_t));
				#endif

				goto mk;
			}
			#ifdef CLOFN_PRINT_HEADER
				else printf("%02X ", *(uint8_t *)(prototype + offset));
			#endif
		}
		#ifdef CLOFN_PRINT_HEADER
			puts("...");
		#endif

		printf("Clofn: could't find closure declaration at prototype function (%08X)!\n", prototype);
		return NULL;
	}
	#ifdef CLOFN_PRINT_HEADER
		else {
			printf("Clofn: prototype header (%08X) { ", prototype);
			for (size_t i = 0; i < phsize; i++) {
				printf("%02X ", *(uint8_t *)(prototype + i));
			}
			printf("} @%u+%u\n", offset, sizeof(uintptr_t));
		}
	#endif

	mk:;

	#if defined(__x86_64__) || defined(__x86_64) || defined(__amd64) || defined(__amd64__) || defined(_WIN64)
		size_t ihsize = offset + sizeof(void *) * 2 + 5;
	#elif defined(i386) || defined(__i386__) || defined(_X86_) || defined(__i386) || defined(__i686__) || defined(__i686) || defined(_WIN32)
		size_t ihsize = offset + sizeof(void *) * 2 + 1;
	#else
		#error Clofn: not support this arch!
	#endif

	void *instance = malloc(ihsize);
	if (!_clofn_active_memory(instance, ihsize)) {
		puts("Clofn: could't change memory type of C.malloc allocated!");
		free(instance);
		return NULL;
	}
	memcpy(instance, prototype, offset);
	uintptr_t current = (uintptr_t)instance + offset;
	*(void **)current = data;
	current += sizeof(void *);

	#if defined(__x86_64__)  || defined(__x86_64)  || defined(__amd64)  || defined(__amd64__) || defined(_WIN64)
		*(uint8_t *)current = 0x50;
		current++;
		*(uint8_t *)current = 0x48;
		current++;
		*(uint8_t *)current = 0xB8;
		current++;
		*(uintptr_t *)current = (uintptr_t)prototype + offset + sizeof(uintptr_t) - 1; // 0x58 in _CLOFN_SCIENCE_NUMBER
		current += sizeof(uintptr_t);
		*(uint16_t *)current = 0xE0FF;
	#elif defined(i386) || defined(__i386__) || defined(_X86_) || defined(__i386) || defined(__i686__) || defined(__i686) || defined(_WIN32)
		*(uint8_t *)current = 0xE9;
		current++;
		*(uintptr_t *)current = ((uintptr_t)prototype + offset + sizeof(uintptr_t)) - ((uintptr_t)instance + ihsize);
	#endif

	#ifdef CLOFN_PRINT_HEADER
		printf("Clofn: instance header (%08X) { ", instance);
		for (size_t i = 0; i < ihsize; i++) {
			printf("%02X ", *(uint8_t *)(instance + i));
		}
		printf("}\n");
	#endif

	return instance;
}

#define new_clofn(name, closure_value) _new_clofn(_clofn__##name, &_clofn__##name##__phsize, (void *)closure_value)

#ifdef __cplusplus
}
#endif

#endif // !_CLOFN_H
