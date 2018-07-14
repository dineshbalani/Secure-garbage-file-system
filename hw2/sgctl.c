#include <sys/ioctl.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <openssl/md5.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#define SGFS_IOCSETD  _IOW(SGFS_MAGIC, 2 , char *)
#define SGFS_MAGIC 's'

int main(int argc, char * const argv[])
{

    int err=0;
    int option = 0;
    int fd = 0;
    unsigned char* md = (unsigned char*)malloc(16*sizeof(unsigned char));
    unsigned char* deletefile = (unsigned char*)malloc(16*sizeof(unsigned char));

    if ((option = getopt (argc, argv, "u")) != -1){
        if(argc<3){
            printf("Please enter file name\n");
            return -1;
        }
        deletefile = argv[optind];
        printf("INFO : File to undelete%s\n",deletefile);
        fd = open(deletefile, O_RDONLY);
        if(fd < 0){
            printf("Could Not Open Descriptor\n");
            return 1;
        }
        err = ioctl(fd, SGFS_IOCSETD, md);
        if (err == 0)
            printf("File Succefully Un-Deleted\n", err);
        else
            printf("syscall returned %d (errno=%d)\n", err, errno);
        close(fd);
    }
    else{
        printf("Invalid command\n");
    }
    return 0;
}