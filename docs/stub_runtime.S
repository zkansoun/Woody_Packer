    .intel_syntax noprefix
    .text
    .global woody_stub
woody_stub:
    /* Save registers */
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12

    /* Print banner */
    mov eax, 1
    mov edi, 1
    lea rsi, [rip + banner]
    mov edx, 14
    syscall

    /* Load metadata pointer */
    lea rsi, [rip + metadata]

    /* Derive ASLR slide (actual metadata address - link-time address) */
    mov rbx, rsi
    mov rdx, [rsi + 24]
    sub rbx, rdx          /* rbx now holds the load bias */
    
    /* Load decryption parameters */
    mov r8, [rsi + 8]     /* enc_region_start */
    add r8, rbx
    mov rcx, [rsi + 16]   /* enc_region_size */
    lea r9, [rsi + 32]    /* key start */
    lea r12, [rsi + 64]   /* key end */
    mov r10, r9           /* current key ptr */
    
    /* Skip if nothing to decrypt */
    test rcx, rcx
    jz .Ldecrypt_done
    
    /* mprotect */
    push rcx
    mov rdi, r8
    and rdi, 0xfffffffffffff000
    mov rax, r8
    add rax, rcx
    sub rax, rdi
    add rax, 0xfff
    and rax, 0xfffffffffffff000
    mov rsi, rax
    mov edx, 7
    mov eax, 10
    syscall
    pop rcx
    
.Ldecrypt_loop:
    movzx ebx, byte ptr [r8]
    movzx edx, byte ptr [r10]
    xor bl, dl
    mov byte ptr [r8], bl
    
    inc r8
    inc r10
    cmp r10, r12
    jne .Lkey_ok
    mov r10, r9
.Lkey_ok:
    dec rcx
    jnz .Ldecrypt_loop
    
.Ldecrypt_done:
    /* Load original entry point */
    lea rsi, [rip + metadata]
    mov rbx, rsi
    mov rdx, [rsi + 24]
    sub rbx, rdx
    mov rax, [rsi]
    add rax, rbx
    
    /* Restore all registers */
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    add rsp, 8  /* Skip old rax */
    
    /* Jump to original entry */
    jmp rax

banner:
    .ascii "....WOODY....\n"
    .byte 0
    .p2align 3
metadata:
    .zero 64

