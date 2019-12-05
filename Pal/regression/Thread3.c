#include <stdatomic.h>

#include "pal.h"
#include "pal_debug.h"

volatile bool dummy_true = true;

static atomic_bool thread2_started = false;
static atomic_bool thread3_started = false;
static atomic_bool thread3_exit_ok = true;
static atomic_bool thread4_started = false;
static atomic_bool thread5_started = false;
static atomic_bool thread6_started = false;
static atomic_bool thread7_started = false;
static atomic_bool thread8_started = false;
static atomic_bool thread9_started = false;

int thread2_run(void* args) {
    pal_printf("Thread 2 started.\n");

    thread2_started = true;

    pal_printf("Exiting thread 2 by return.\n");
    return 0;
}

int thread3_run(void* args) {
    pal_printf("Thread 3 started.\n");

    thread3_started = true;

    pal_printf("Exiting thread 3 by DkThreadExit.\n");

    // Ensure that the compiler can't know that this should never return.
    if (dummy_true) {
        DkThreadExit();
    }

    thread3_exit_ok = false;
    pal_printf("Exiting thread 3 failed.\n");

    return 0;
}

int thread4_run(void* args) {
    pal_printf("Thread 4 started.\n");

    thread4_started = true;

    pal_printf("Exiting thread 4 by return.\n");
    return 0;
}

int thread5_run(void* args) {
    pal_printf("Thread 5 started.\n");

    thread5_started = true;

    pal_printf("Exiting thread 5 by return.\n");
    return 0;
}

int thread6_run(void* args) {
    pal_printf("Thread 6 started.\n");

    thread6_started = true;

    pal_printf("Exiting thread 6 by return.\n");
    return 0;
}

int thread7_run(void* args) {
    pal_printf("Thread 7 started.\n");

    thread7_started = true;

    pal_printf("Exiting thread 7 by return.\n");
    return 0;
}

int thread8_run(void* args) {
    pal_printf("Thread 8 started.\n");

    thread8_started = true;

    pal_printf("Exiting thread 8 by return.\n");
    return 0;
}

int thread9_run(void* args) {
    pal_printf("Thread 9 started.\n");

    thread9_started = true;

    pal_printf("Exiting thread 9 by return.\n");
    return 0;
}

// If there's a thread limit, like on SGX, it should be set to exactly 2. There
// should be only the main thread and only one other thread at a time.
int main() {
    pal_printf("Thread 1 (main) started.\n");

    PAL_HANDLE thread2 = DkThreadCreate(thread2_run, NULL);
    if (!thread2) {
        pal_printf("DkThreadCreate failed for thread 2.\n");
        return 1;
    }

    // 1 s should be enough even on a very busy system to start a thread and
    // then exit it again including all cleanup.
    DkThreadDelayExecution(1000000);

    if (thread2_started) {
        pal_printf("Thread 2 ok.\n");
    }

    PAL_HANDLE thread3 = DkThreadCreate(thread3_run, NULL);
    if (!thread3) {
        pal_printf("DkThreadCreate failed for thread 3.\n");
        return 1;
    }

    DkThreadDelayExecution(1000000);

    if (thread3_started && thread3_exit_ok) {
        pal_printf("Thread 3 ok.\n");
    }

    PAL_HANDLE thread4 = DkThreadCreate(thread4_run, NULL);
    if (!thread4) {
        pal_printf("DkThreadCreate failed for thread 4.\n");
        return 1;
    }

    DkThreadDelayExecution(1000000);

    if (thread4_started) {
        pal_printf("Thread 4 ok.\n");
    }

    PAL_HANDLE thread5 = DkThreadCreate(thread5_run, NULL);
    if (!thread5) {
        pal_printf("DkThreadCreate failed for thread 5.\n");
        return 1;
    }

    DkThreadDelayExecution(1000000);

    if (thread5_started) {
        pal_printf("Thread 5 ok.\n");
    }

    PAL_HANDLE thread6 = DkThreadCreate(thread6_run, NULL);
    if (!thread6) {
        pal_printf("DkThreadCreate failed for thread 6.\n");
        return 1;
    }

    DkThreadDelayExecution(1000000);

    if (thread6_started) {
        pal_printf("Thread 6 ok.\n");
    }

    PAL_HANDLE thread7 = DkThreadCreate(thread7_run, NULL);
    if (!thread7) {
        pal_printf("DkThreadCreate failed for thread 7.\n");
        return 1;
    }

    DkThreadDelayExecution(1000000);

    if (thread7_started) {
        pal_printf("Thread 7 ok.\n");
    }

    PAL_HANDLE thread8 = DkThreadCreate(thread8_run, NULL);
    if (!thread8) {
        pal_printf("DkThreadCreate failed for thread 8.\n");
        return 1;
    }

    DkThreadDelayExecution(1000000);

    if (thread8_started) {
        pal_printf("Thread 8 ok.\n");
    }

    PAL_HANDLE thread9 = DkThreadCreate(thread9_run, NULL);
    if (!thread9) {
        pal_printf("DkThreadCreate failed for thread 9.\n");
        return 1;
    }

    DkThreadDelayExecution(1000000);

    if (thread9_started) {
        pal_printf("Thread 9 ok.\n");
    }

    return 0;
}



