#include <string.h>
#include <stdio.h>

//Simple BoF by b1ack0wl for E1550

int main(int argc, char **argv[]){
char buf[200] ="\0";

if (argc < 2){
printf("Usage: stack_bof_01 <argument>\r\n-By b1ack0wl\r\n");
exit(1);
} 


printf("Welcome to the first BoF exercise!\r\n\r\n"); 
strcpy(buf, argv[1]);

printf("You entered %s \r\n", buf);
printf("Try Again\r\n");

return 0x41; // Just so you can see what register is populated for return statements
}

void dat_shell(){
printf("Congrats! I will now execute /bin/sh\r\n- b1ack0wl\r\n");
system("/bin/sh -c");

//execve("/bin/sh","-c",0);
//execve("/bin/sh", 0, 0);
exit(0);

}
