from pwn import *
context.arch = "amd64"
context.bits = 64

s = "".join([chr(ord(i)-10) for i in "flag{letsgetbusy}"])
ss = [u64(s[i:i+8].ljust(8, '\x00')) for i in range(0, len(s), 8)]
print("The pieces: {}, len: {}".format([hex(i) for i in ss], len(ss))) 

asmcode = """
MAIN:
    mov rax, {}
    push rax
    mov rax, {}
    push rax
    mov rax, {}
    push rax
    mov rdx, rsp
    mov rcx, 0
    
CHECK:
    cmp rcx, {}
    je END
    
    mov al, BYTE PTR[rdx]
    add al, 10
    mov BYTE PTR[rdx], al
    inc rdx
    inc rcx
    jmp CHECK

END:
    mov rax, 60 # exit syscall
    syscall
    ret
""".format(ss[2], ss[1], ss[0], len(s))

print(disasm(asm(asmcode)))
with open("runme", "wb") as f:
    f.write(make_elf(asm(asmcode)))
