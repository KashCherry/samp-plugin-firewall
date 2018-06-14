/*	Copyright 2018 (c) RakLabs

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/
/*
//	Welcome to scalehook source code.
//	If you want know what's that, then read:
//		scalehook - cross-platform C/C++ hooking library.
//
//	It will be very helpful for you, if you want:
//		* know your security troubles <3
//		* hook any function c:
//		* something else?
//
//	Functions:
//		scalehook_unprotect(void *src, size_t size) - Getting access.
//
//		scalehook_create() - Create a hook (returns scalehook structure or nothing).
//		scalehook_destroy() - Destroy a hook. It very important! If you don't want memory leak (no return anything).
//		scalehook_create_fast() - Create a hook (with settings by default) (returns scalehook structure or nothing).
//		scalehook_fast_hook() - Fast hook (returns true/false).
//
//		scalehook_get_original_address() - Get hook original address
//		scalehook_jmp_get_opcode() - Get hook opcodes
//		scalehook_jmp_get_src() - Get source.
//		scalehook_jmp_get_dst() - Get dest.
//		scalehook_is_installed() - Get installing state
//		scalehook_is_unprotected() - Get unprotecting state
//		scalehook_jmp_get_size() - Get size
//
//	Structures:
//		scalehook_t - scalehook structure
//
//	Definited types:
//		opcode_t (unsigned char).
//		bytes_t (unsigned char *).
//
//	Opcodes:
//		Definited opcodes: jmp & call
//		Any opcodes
//
//	Supports:
//		Windows/Linux (x32/x64) (other OS didn't tested).
*/
#ifndef SCALEHOOK_H_
#define SCLAEHOOK_H_
#include <stdlib.h>
#include <string.h>

#if defined(__i386__) || defined(_X86_) || defined(_M_IX86)
#define scalehook_x86
#define scalehook_jmp_size 5
#elif defined(__AMD64__) || defined(__x86_64__) || defined(_M_AMD64)
#define scalehook_x86_x64
#define scalehook_jmp_size 5
#endif

#if !defined(scalehook_x86) && !defined(scalehook_x86_x64)
#error "Unsupported architecture."
#endif

#if defined (__WIN32__) || defined (_WIN32) || defined(WIN32) || defined(__WIN64__) || defined(_WIN64) || defined(WIN64)
#define scalehook_windows
#elif defined(__LINUX__) || defined(__linux__) || defined(__linux) || defined(FREEBSD) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
#define scalehook_unix
#include <stddef.h>
#endif

#if !defined scalehook_windows && !defined scalehook_unix
#error "Unknown OS."
#endif

#if defined __cplusplus
#define scalehook_cpp
#else
#define scalehook_c
#endif

#ifdef scalehook_cpp
#define scalehook_extern_c extern "C"
#else
#define scalehook_extern_c
#endif

#ifdef scalehook_windows
#define scalehook_call __stdcall
#define scalehook_export scalehook_extern_c
#else
#define scalehook_call
#define scalehook_export scalehook_extern_c
#endif

// -------------------------------------------------

#define scalehook_opcode_jmp	0xE9
#define scalehook_opcode_call	0xE8

// -------------------------------------------------

typedef unsigned char *bytes_t;
typedef unsigned char opcode_t;
#ifdef scalehook_x86_x64
typedef unsigned long long address_t;
#else
typedef unsigned long address_t;
#endif

// -------------------------------------------------

typedef struct
{
	void *src;
	void *dst;
	opcode_t opcode;
	size_t size;
	void *original_bytes;
    bytes_t new_bytes;
	address_t relative_address;
} scalehook_jmp_t;

// -------------------------------------------------

typedef struct
{
	scalehook_jmp_t *scalehook_jmp;
	address_t original_address;
	int installed;
	int unprotected;
} scalehook_t;

// -------------------------------------------------

scalehook_export int scalehook_call scalehook_unprotect(void *src, size_t size);

scalehook_export int scalehook_call scalehook_execute_bytes(bytes_t bytes, void *src, size_t size);
scalehook_export scalehook_jmp_t *scalehook_call scalehook_create_jmp(void *src, void *dst, size_t size, opcode_t opcode);
scalehook_export int scalehook_call scalehook_execute_jmp(scalehook_jmp_t *scalehook_jmp);

scalehook_export scalehook_t *scalehook_call scalehook_create(void *src, void *dst, size_t size, opcode_t opcode);
scalehook_export scalehook_t *scalehook_call scalehook_create_fast(void *src, void *dst);
scalehook_export int scalehook_call scalehook_fast_hook(void *src, void *dst);
scalehook_export int scalehook_call scalehook_destroy(scalehook_t *scalehook);

scalehook_export int scalehook_call scalehook_install(scalehook_t *scalehook);
scalehook_export int scalehook_call scalehook_uninstall(scalehook_t *scalehook);

scalehook_export address_t scalehook_call scalehook_get_original_address(scalehook_t *scalehook);
scalehook_export int scalehook_call scalehook_is_installed(scalehook_t *scalehook);
scalehook_export int scalehook_call scalehook_is_unprotected(scalehook_t *scalehook);

scalehook_export void *scalehook_call scalehook_jmp_get_src(scalehook_jmp_t *scalehook_jmp);
scalehook_export void *scalehook_call scalehook_jmp_get_dst(scalehook_jmp_t *scalehook_jmp);
scalehook_export opcode_t scalehook_call scalehook_jmp_get_opcode(scalehook_jmp_t *scalehook_jmp);
scalehook_export size_t scalehook_call scalehook_jmp_get_size(scalehook_jmp_t *scalehook_jmp);
scalehook_export void *scalehook_call scalehook_jmp_get_original_bytes(scalehook_jmp_t *scalehook_jmp);
scalehook_export bytes_t scalehook_call scalehook_jmp_get_new_bytes(scalehook_jmp_t *scalehook_jmp);
scalehook_export address_t scalehook_call scalehook_jmp_get_relative_address(scalehook_jmp_t *scalehook_jmp);

#endif // SCALEHOOK_H_
