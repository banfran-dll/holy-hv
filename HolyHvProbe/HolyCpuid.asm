; HolyCpuid.asm -- 64-bit CPUID wrapper for the HolyHvProbe driver.
;
; void HolyDoCpuid(
;     UINT64  rax_in,        ; rcx
;     UINT64  rcx_in,        ; rdx
;     UINT64* regs_out       ; r8 -> &qword[4]   { RAX, RBX, RCX, RDX }
; );
;
; MSVC inline asm is unavailable in kernel-mode x64. This routine lets us
; round-trip the full 64-bit GPRs through the hv hook -- guest RBX is the
; low 64 bits of a kernel-space pointer (e.g. 0xFFFFF807'C5118A0), and the
; __cpuidex intrinsic only exposes the low 32 bits of each output reg.

PUBLIC HolyDoCpuid

.code

HolyDoCpuid PROC
    push    rbx
    push    rsi

    mov     rsi, r8                 ; rsi = regs_out
    mov     rax, rcx                ; rax = rax_in
    mov     rcx, rdx                ; rcx = rcx_in
    cpuid
    mov     qword ptr [rsi +  0], rax
    mov     qword ptr [rsi +  8], rbx
    mov     qword ptr [rsi + 16], rcx
    mov     qword ptr [rsi + 24], rdx

    pop     rsi
    pop     rbx
    ret
HolyDoCpuid ENDP

END
