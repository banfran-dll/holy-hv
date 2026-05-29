.code
TriggerBackdoor PROC
    push rbx
    push rcx
    push rdx
    
    mov rcx, 0aabbccdd12345h
    mov rdx, 1
    cpuid
    
    ; CPUID return values are in EAX, EBX, ECX, EDX
    ; We need to return the value in RAX, which CPUID modifies.
    ; So we don't need to do anything special, RAX is already set.

    pop rdx
    pop rcx
    pop rbx
    ret
TriggerBackdoor ENDP
END
