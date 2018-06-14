# scalehook
cross-platform C/C++ hooking library. I hope this library will be very useful for your project.

## Important
If you have errors with C++ compilation, just change file extension on .cpp. Example: `scalehook.c => scalehook.cpp`

## Functions
Here are all scalehook's functions.
```c
scalehook_export scalehook_t *scalehook_call scalehook_create(void *src, void *dst, size_t size, opcode_t opcode); // create a hook
scalehook_export scalehook_t *scalehook_call scalehook_create_fast(void *src, void *dst); // scalehook_create with arguments by default
scalehook_export int scalehook_call scalehook_fast_hook(void *src, void *dst); // create hook fast (not return hook handle)
scalehook_export int scalehook_call scalehook_destroy(scalehook_t *scalehook); // destroy hook (this is to avoid a memory leak)

scalehook_export int scalehook_call scalehook_install(scalehook_t *scalehook); // install already created hook
scalehook_export int scalehook_call scalehook_uninstall(scalehook_t *scalehook); // uninstall already created hook
```

Functions for getting information about hook:<br>
```c
scalehook_export unsigned long scalehook_call scalehook_get_original_address(scalehook_t *scalehook);
scalehook_export int scalehook_call scalehook_is_installed(scalehook_t *scalehook);
scalehook_export int scalehook_call scalehook_is_unprotected(scalehook_t *scalehook);

scalehook_export void *scalehook_call scalehook_jmp_get_src(scalehook_jmp_t *scalehook_jmp);
scalehook_export void *scalehook_call scalehook_jmp_get_dst(scalehook_jmp_t *scalehook_jmp);
scalehook_export opcode_t scalehook_call scalehook_jmp_get_opcode(scalehook_jmp_t *scalehook_jmp);
scalehook_export size_t scalehook_call scalehook_jmp_get_size(scalehook_jmp_t *scalehook_jmp);
scalehook_export void *scalehook_call scalehook_jmp_get_original_bytes(scalehook_jmp_t *scalehook_jmp);
scalehook_export bytes_t scalehook_call scalehook_jmp_get_new_bytes(scalehook_jmp_t *scalehook_jmp);
scalehook_export unsigned long scalehook_call scalehook_jmp_get_relative_address(scalehook_jmp_t *scalehook_jmp);
```

## Example
Simple hook.
```c
#include <stdio.h>
#include "scalehook.h"

scalehook_t *new_hook;
typedef void(*original)();

void kek()
{
  printf("2: Success hooked.\n");
  printf("3: Calling original function..\n");
  scalehook_uninstall(new_hook);
  ((original)new_hook->original_address)();
  scalehook_install(new_hook);
}

void lol()
{
  printf("lol\n");
}

int main(void)
{
  new_hook = scalehook_create(lol, kek, 5, scalehook_opcode_jmp, scalehook_type_call);
  if(!new_hook)
  {
    printf("1: Hook failed.\n");
  }
  lol();
  scalehook_destroy(new_hook);
  return 0;
}
```
Now let's get information about hook.
```c
// Take code from the previous example

void kek()
{
  printf("2: Success hooked.\n");
  printf("Hook size: %d\n", scalehook_jmp_get_size(scalehook->scalehook_jmp));
}
```
So easy, isn't it?

## Test
If you want to test scalehook, then:
1. Clone this repository
2. Enter in terminal: `make`
3. Done.
