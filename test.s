.global _start
.intel_syntax noprefix
_start:
        push ebp
        mov  ebp,esp
        mov eax, 1
        mov ebx, 42
        sub ebx, 20
        int 0x80
        ret
