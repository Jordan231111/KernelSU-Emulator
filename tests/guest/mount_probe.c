#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
int main(int argc,char**argv){if(argc<2)return 2;if(argc>3&&unshare(CLONE_NEWNS)){perror("unshare");return 3;}if(argc>2){const char*c="u:r:untrusted_app:s0";int f=open("/proc/self/attr/current",O_WRONLY);if(f<0)return 4;if(setgroups(0,NULL)||setgid(19999)||setuid(19999))return 5;if(write(f,c,strlen(c))<0)return 4;close(f);prctl(PR_SET_DUMPABLE,1);}
printf("uid=%u\n",getuid());FILE*in=fopen("/proc/self/mountinfo","r");if(!in){perror("mountinfo");return 6;}char*line=NULL;size_t n=0;int found=0;while(getline(&line,&n,in)>0)if(strstr(line,"/ksu-qa-") && strstr(line,"/mount ")){printf("mount=%s",line);found++;}free(line);fclose(in);printf("mount_visible=%d\n",found);int fd=open(argv[1],O_RDONLY);if(fd<0){perror("open file");return 7;}char name[100],b[1024]={0};snprintf(name,sizeof(name),"/proc/self/fdinfo/%d",fd);int f=open(name,O_RDONLY);if(f<0){perror("fdinfo");return 8;}int got=read(f,b,sizeof(b)-1);if(got>0)printf("fdinfo=%s",b);close(f);close(fd);return 0;}
