#ifndef _BOOX_H
#define _BOOX_H

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BOOX_ADDRESSING_RANGE 1024
#define _BOOX_NUM 0x58ffffbffdffffafULL

#if defined(__unix__)
	#include <sys/mman.h>
	#include <sys/user.h>
	bool _booxActiveMemory(void *ptr, size_t size) {
		return mprotect((void *)(((size_t)ptr >> PAGE_SHIFT) << PAGE_SHIFT), size, PROT_READ | PROT_EXEC | PROT_WRITE) == 0;
	}
#elif defined(_WIN32)
	#include <windows.h>
	bool _booxActiveMemory(void *ptr, size_t size) {
		DWORD oldProtect;
		return VirtualProtect(ptr, size, PAGE_EXECUTE_READWRITE, &oldProtect);
	}
#else
	#pragma message("Boox: not support this OS!")
#endif

#define booxDataDecl(type, name) type name = (type)_BOOX_NUM

void *booxMakeFunc(void *rawFunc, void *data) {
	#ifdef BOOX_PRINT_HEADER
		printf("Boox: raw header (%08X) { ", (size_t)rawFunc);
	#endif
	for (size_t offset = 0; offset < BOOX_ADDRESSING_RANGE; offset++) {
		if (*(size_t *)((size_t)rawFunc + offset) == (size_t)_BOOX_NUM) {
			#ifdef BOOX_PRINT_HEADER
				printf("} @%u+%u\n", offset, sizeof(size_t));
			#endif

			#if defined(__x86_64__) || defined(__x86_64) || defined(__amd64) || defined(__amd64__) || defined(_WIN64)
				size_t bxFuncSize = offset + sizeof(size_t) * 2 + 5;
			#elif defined(i386) || defined(__i386__) || defined(_X86_) || defined(__i386) || defined(__i686__) || defined(__i686) || defined(_WIN32)
				size_t bxFuncSize = offset + sizeof(size_t) * 2 + 1;
			#else
				#pragma message("Boox: not support this arch!")
			#endif

			void *bxFunc = malloc(bxFuncSize);
			if (!_booxActiveMemory(bxFunc, bxFuncSize)) {
				puts("Boox: could't change memory type of C.malloc allocated!");
				free(bxFunc);
				return NULL;
			}
			memcpy(bxFunc, rawFunc, offset);
			size_t addr = (size_t)bxFunc + offset;
			*(size_t *)addr = (size_t)data;
			addr += sizeof(size_t);

			#if defined(__x86_64__)  || defined(__x86_64)  || defined(__amd64)  || defined(__amd64__) || defined(_WIN64)
				*(uint8_t *)addr = 0x50;
				addr++;
				*(uint8_t *)addr = 0x48;
				addr++;
				*(uint8_t *)addr = 0xB8;
				addr++;
				*(size_t *)addr = (size_t)(rawFunc + offset + sizeof(size_t) - 1); // 0x58 in _BOOX_NUM
				addr += sizeof(size_t);
				*(uint16_t *)addr = 0xE0FF;
			#elif defined(i386) || defined(__i386__) || defined(_X86_) || defined(__i386) || defined(__i686__) || defined(__i686) || defined(_WIN32)
				*(uint8_t *)addr = 0xE9;
				addr++;
				*(size_t *)addr = ((size_t)rawFunc + offset + sizeof(size_t)) - ((size_t)bxFunc + bxFuncSize);
			#endif

			#ifdef BOOX_PRINT_HEADER
				printf("Boox: new header (%08X) { ", (size_t)bxFunc);
				for (size_t i = 0; i < bxFuncSize; i++) {
					printf("%02X ", *(uint8_t *)(bxFunc + i));
				}
				printf("}\n");
			#endif

			return bxFunc;
		}
		#ifdef BOOX_PRINT_HEADER
			else printf("%02X ", *(uint8_t *)(rawFunc + offset));
		#endif
	}
	#ifdef BOOX_PRINT_HEADER
		printf("...\n");
	#endif

	printf("Boox: could't find declarations at raw function (%08X)!\n", (size_t)rawFunc);
	return NULL;
}

#ifdef __cplusplus
}
#endif

#endif // !_BOOX_H
