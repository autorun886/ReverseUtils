/* Small real-process fixture: recursion, hot calls, worker thread, DLL reload. */
#include <stdint.h>
#ifdef _WIN32
#include <windows.h>
#define EXPORT __declspec(dllexport) __attribute__((noinline))
#define PAUSE(ms) Sleep(ms)
#else
#include <pthread.h>
#include <unistd.h>
#include <dlfcn.h>
#define EXPORT __attribute__((visibility("default"), noinline))
#define PAUSE(ms) usleep((ms) * 1000)
#endif

EXPORT int fixture_recursive(int value) {
    if (value <= 0) return 1;
    volatile int result = fixture_recursive(value - 1);
    return result + value;
}

EXPORT int fixture_hot(int value, const char *text) {
    return value + (text ? text[0] : 0);
}

#ifndef FIXTURE_DLL
static volatile int sink;
#ifdef _WIN32
static DWORD WINAPI worker(void *unused) {
#else
static void *worker(void *unused) {
#endif
    (void)unused;
    for (;;) {
        sink = fixture_hot(7, "worker");
        PAUSE(10);
    }
    return 0;
}

int main(int argc, char **argv) {
#ifdef _WIN32
    HANDLE thread = CreateThread(NULL, 0, worker, NULL, 0, NULL);
    CloseHandle(thread);
#else
    pthread_t thread;
    pthread_create(&thread, NULL, worker, NULL);
#endif
    for (;;) {
        sink = fixture_recursive(4);
        for (int i = 0; i < 20; ++i) sink = fixture_hot(i, "main");
        if (argc > 1) {
#ifdef _WIN32
            HMODULE module = LoadLibraryA(argv[1]);
            if (module) {
                int (*call)(int) = (int (*)(int))GetProcAddress(module, "fixture_recursive");
                if (call) sink = call(3);
                FreeLibrary(module);
            }
#else
            void *module = dlopen(argv[1], RTLD_NOW);
            if (module) {
                int (*call)(int) = (int (*)(int))dlsym(module, "fixture_recursive");
                if (call) sink = call(3);
                dlclose(module);
            }
#endif
        }
        PAUSE(25);
    }
}
#endif
