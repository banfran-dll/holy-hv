// cpuid_voyager.c — build with: cl /nologo cpuid_voyager.c
#include <intrin.h>
#include <stdio.h>
int main(void) {
    int r[4] = {0};
    __cpuidex(r, 0, 0xDEADC0DE);   // EAX = command(0), ECX = KEY
    printf("eax=%08X ebx=%08X ecx=%08X edx=%08X\n",
           r[0], r[1], r[2], r[3]);
    return 0;
}
