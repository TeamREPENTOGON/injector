This is a general purpose DLL injector. 

It is inspired by the [SKSE injector](https://github.com/ianpatt/skse64) for
Skyrim. Thanks to ianpatt for his invaluable help when I started working on
this.

The purpose of the injector is to start an executable and inject a DLL in its
memory, then run a given entry point. This couples well with a hook system,
such as the one provided by ZHL, in order to safely redirect functions in
the executable before it runs its `main` function.

# Injecting a DLL

The core function of the injector is `injector_inject`. This function starts a given
executable with a given command-line, then injects a given DLL in its memory,
runs a given entry point in the DLL with given data, then yields back control
to the caller once the injection is done. The caller is provided with handles
to the process and its main thread.

```c
int injector_inject(const char* executable, const char* cli, int steam_appid,
    const char* loaded_library, const char* entry_point, void* injected_data,
    size_t injected_data_size, HANDLE* thread, HANDLE* process);
```

* `executable`: a path (relative or absolute) to the executable to run, and in
the memory of which the DLL will be injected.
* `cli`: the command-line to run. It can be `NULL`, in which case it is
substituted with the full path to the executable. It is not necessary to prefix
the command-line with the full path to the executable: the function will take
care of this step.
* `steam_appid`: if set to a strictly positive value, a file called
`steam_appid.txt`, containing this value, will be created next to the
executable. If such a file already exists, the parameter is ignored.
* `loaded_library`: path to the library to inject in the executable. Standard
rules for finding libraries through `LoadLibraryA` apply.
* `entry_point`: decorated name of the symbol in the library that will act
as the entry point. The corresponding function shall have a `__cdecl`
calling convention if targeting x86. Its signature shall be `int (void*)`.
* `injected_data`: a pointer to the data to be passed as parameter to the
entry point. This data is copied as-is in the memory of the executable before
loading the library through `WriteProcessMemory`.
* `injected_data_size`: the length (in bytes) of the memory block pointed by
`injected_data`.
* `thread`: out parameter. Receives the handle to the main thread of the
newly created process. Call `CloseHandle` on it once you're done.
* `process`: out parameter. Receives the handle to the process itself. Call
`CloseHandle` on it once you're done.

The function returns `0` on success, a non-zero value on error.

# Debugging

In case of errors, three functions are at your disposal:
* `int injector_error()`: returns an error code describing the latest error.
* `const char* injector_strerror(int error)`: returns a human-readable description
of the given error.
* `const char* injector_win32_fn()`: returns the name of the latest Win32 call
that errored.

If `injector_error` returns the value `INJECT_RESULT_LAST_ERROR`, then the last
error occured in the Win32 API, in which case `injector_win32_fn` will give you
the call that errored and `GetLastError()` will give you extended information.

# Warning

Properly injecting a DLL in the memory of another process is a difficult (and
dangerous) process. Use this at your own risk.

# Licence

This software is [licensed](LICENSE) under the MIT licence.
