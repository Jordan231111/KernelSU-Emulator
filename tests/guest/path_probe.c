#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
int main(int argc,char**argv){if(argc<2)return 2; if(argc>2){const char*c="u:r:untrusted_app:s0";int f=open("/proc/self/attr/current",O_WRONLY);if(f<0){perror("open context");return 3;}if(setgroups(0,NULL)||setgid(19999)||setuid(19999)){perror("drop");return 4;}if(write(f,c,strlen(c))<0){perror("setcon");return 3;}close(f);}
 printf("uid=%u\n",getuid());struct stat st;errno=0;int r=stat(argv[1],&st);printf("stat=%d errno=%d\n",r,errno);if(!r)printf("ino=%lu size=%lld mode=%o\n",(unsigned long)st.st_ino,(long long)st.st_size,st.st_mode&07777);errno=0;int fd=open(argv[1],O_RDONLY);printf("open=%d errno=%d\n",fd,errno);if(fd>=0)close(fd);errno=0;fd=open(argv[1],O_PATH);printf("opath=%d errno=%d\n",fd,errno);if(fd>=0)close(fd);char b[512];snprintf(b,sizeof(b),"%s",argv[1]);char*tail=strrchr(b,'/');if(!tail)return 5;*tail++=0;DIR*d=opendir(b);if(!d){perror("opendir");return 6;}int seen=0;struct dirent*e;while((e=readdir(d)))if(!strcmp(e->d_name,tail))seen++;closedir(d);printf("dirent=%d\n",seen);return 0;}
