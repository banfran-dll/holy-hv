; HolyCpuid.asm -- 64-bit CPUID wrapper for the HolyHvProbe driver.

PUBLIC HolyDoCpuid
PUBLIC HolyDoCpuidEx

.code

; void HolyDoCpuid(UINT64 rax_in, UINT64 rcx_in, UINT64* regs_out);
;   rcx = rax_in, rdx = rcx_in, r8 = regs_out -> {RAX, RBX, RCX, RDX}
HolyDoCpuid PROC
    push    rbx
    push    rsi
    mov     rsi, r8
    mov     rax, rcx
    mov     rcx, rdx
    cpuid
    mov     qword ptr [rsi +  0], rax
    mov     qword ptr [rsi +  8], rbx
    mov     qword ptr [rsi + 16], rcx
    mov     qword ptr [rsi + 24], rdx
    pop     rsi
    pop     rbx
    ret
HolyDoCpuid ENDP

; void HolyDoCpuidEx(UINT64 rax_in, UINT64 rcx_in, UINT64 rdx_in,
;                    UINT64 r8_in,  UINT64* regs_out);
;   rcx = rax_in, rdx = rcx_in, r8 = rdx_in, r9 = r8_in,
;   [rsp+0x28] = regs_out  (5th arg via stack per MS x64 ABI)
HolyDoCpuidEx PROC
    ; MS x64 ABI on entry:
    ;   [rsp+0]    = return addr
    ;   [rsp+8..28]= shadow space (4 slots, 0x20 bytes)
    ;   [rsp+28]   = arg5 (regs_out)
    push    rbx                          ; -8
    push    rsi                          ; -16
    push    rdi                          ; -24  (total 0x18)
    ; arg5 is now at [rsp + 0x28 + 0x18] = [rsp + 0x40]
    mov     rdi, qword ptr [rsp + 40h]   ; rdi = regs_out
    mov     r10, r9                      ; r10 = r8_in
    mov     rax, rcx                     ; rax = rax_in
    mov     rcx, rdx                     ; rcx = rcx_in
    mov     rdx, r8                      ; rdx = rdx_in
    mov     r8,  r10                     ; r8  = r8_in
    cpuid
    mov     qword ptr [rdi +  0], rax
    mov     qword ptr [rdi +  8], rbx
    mov     qword ptr [rdi + 16], rcx
    mov     qword ptr [rdi + 24], rdx
    pop     rdi
    pop     rsi
    pop     rbx
    ret
HolyDoCpuidEx ENDP

END
