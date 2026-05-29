#include <windows.h>
#include <stdio.h>

extern unsigned long long TriggerBackdoor();

int main()
{
    printf("Executing CPUID backdoor check...\n");
    
    __try {
        unsigned long long result = TriggerBackdoor();
        printf("Result: 0x%llX\n", result);
        
        if (result == 0x123456789ULL) {
            printf("\n[SUCCESS] HOLY HYPERVISOR IS ACTIVE AND BACKDOOR RESPONDED!\n");
        } else {
            printf("\n[FAILED] Backdoor failed to respond (Unexpected value).\n");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("\n[ERROR] CPUID instruction crashed! The backdoor is not active.\n");
    }

    return 0;
}
