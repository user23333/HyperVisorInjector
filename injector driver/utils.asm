.code

extern RetInstruction:QWORD
extern RopGadgetAddress:QWORD

align 10h

CalloutInterrupt proc

push rdi
push rsi
push rbp

mov rax, rcx 
lea r10, [rsp + 20h] 
sub rsp, 10h 

sub rdx, 138h

mov rcx, [RetInstruction]
mov [rdx + 110h], rcx

mov ecx, cs
mov [rdx + 118h], rcx

pushfq
pop rcx
mov [rdx + 120h], rcx 

lea rcx, [ReturnLoc]
mov [rsp], rcx							
mov [rdx + 128h], rsp

mov ecx, ss
mov [rdx + 130h], rcx

mov rcx, [RetInstruction]
mov [rdx + 28h], rcx

lea rbp, [rdx + 28h]

test r8, r8
jz no_sub_rsp

lea r11, [r8 * 8]
sub rdx, r11

and rdx, 0FFFFFFFFFFFFFFF0h

lea rsi, [r10 + 40h]
lea rdi, [rdx + 20h] 
mov rcx, r8 

rep movsq 

xor esi, esi
xor edi, edi

no_sub_rsp:

mov rcx, [RopGadgetAddress]
sub rdx, 8
mov [rdx], rcx

mov ecx, ss
push rcx		
push rdx		
pushfq		

xor [rsp], r9

mov ecx, cs
push rcx		
push rax		

xor eax, eax

mov rcx, [r10 + 20h]
mov rdx, [r10 + 28h]
mov r8, [r10 + 30h]
mov r9, [r10 + 38h]

xor r10, r10

iretq

align 10h

ReturnLoc:
add rsp, 8
pop rbp
pop rsi
pop rdi

ret

CalloutInterrupt endp

align 10h

CalloutReturn proc
    ;push stack segment selector
    mov eax, ss
    push rax

    ;push stack pointer
    mov rax, [rcx + 0]
    push rax

    ;push arithmetic/system flags
    pushfq
    mov rax, [rsp]
    xor rax, 200h ; ebable interrupts
    mov [rsp], rax

    ;push code segment selector
    mov eax, cs
    push rax

    ;push instruction pointer
    mov rax, [rcx + 8]
    push rax

    ;set arguments

    mov rdx, [rcx + 18h]
    mov r8, [rcx + 20h]
    mov r9, [rcx + 28h]
    mov rax, [rcx + 30h]

    mov r12, [rcx + 38h]
    mov r13, [rcx + 40h]
    mov r14, [rcx + 48h]
    mov r15, [rcx + 50h]
    mov rdi, [rcx + 58h]
    mov rsi, [rcx + 60h]
    mov rbx, [rcx + 68h]
    mov rbp, [rcx + 70h]

    mov rcx, [rcx + 10h]

    ;clear trace
    xor rax, rax

    ; goto code
    iretq
CalloutReturn endp

end
