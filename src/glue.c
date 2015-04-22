#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
void *poll_for_broadcasts(void *args);
extern int32_t SuperNET_retval,did_SuperNET_init;
char SuperNET_url[512];

int8_t portable_spawn(char *os, char *cmd, char *argv) //TODO: extend for other OSes
{
    int8_t status = 0;
    if(strcmp("_WIN32",os)==0)
    {
        #ifdef _WIN32
        if(_spawnl(_P_NOWAIT, cmd, cmd, argv, NULL) !=0 )
            status = 1;
        else
            status = 0;
	    #endif  
    } 
    else if(strcmp("__linux__",os)==0)
    {
        #ifndef _WIN32
        pid_t pid = 0;
        pid = fork();
        if(pid==0)//child process
        {
            if ( execl(cmd, argv, NULL) )
		        status = 1;
	        else
		        status = 0;
        }
        #endif
    }
    else
    {
	    #ifndef _WIN32
        char *cmdArgs = (char*)malloc(strlen(cmd)+strlen(argv)+16);
        strcpy(cmdArgs, cmd);
        strcat(cmdArgs, " ");
        strcat(cmdArgs, argv);
	    pid_t pid = 0;
	    pid = fork();
	    if (pid==0)//child process
	    {
            if ( system(cmd) != 0 )
	        status = 1;
	    else
	        status = 0;
	    }
        free(cmdArgs);
		#else
		status = 1;
		#endif
    }
return status;
} 

void *portable_thread_create(void *funcp,void *argp);
/*{
    pthread_t *ptr;
    ptr = (pthread_t *)malloc(sizeof(*ptr));
    if ( pthread_create(ptr,NULL,funcp,argp) != 0 )
    {
        free(ptr);
        return(0);
    } else return(ptr);
}*/

int32_t set_SuperNET_url(char *url)
{
    FILE *fp;
    int32_t retval=0,usessl=0,port=0;
    while ( (fp= fopen("horrible.hack","rb")) == 0 )
        sleep(1);
    if ( fread(&retval,1,sizeof(retval),fp) != sizeof(retval) )
        retval = -2;
    fclose(fp);
    if ( retval > 0 )
    {
        usessl = (retval & 1);
        port = (retval >> 1) & 0xffff;
        if ( port < (1 << 16) )
        {
            sprintf(SuperNET_url,"http%s://127.0.0.1:%d",usessl==0?"":"s",port);// + !usessl);
            retval >>= 17;
            printf("retval.%d port.%d usessl.%d\n",retval,port,usessl);
        }
        else retval = -3;
    }
    switch ( retval )
    {
        case 0: printf("SuperNET file found!\n"); break;
        case -1: printf("SuperNET file NOT found. It must be in the same directory as SuperNET\n"); break;
        case -2: printf("handshake file error\n"); break;
        case -3: printf("illegal supernet port.%d usessl.%d\n",port,usessl); break;
    }
    return(retval);
}

void *_launch_SuperNET(void *_myip)
{
    char *myip = _myip;
    FILE *fp;
    char cmd[128],*osstr,*rmstr,*cmdstr,*msgfname = "horrible.hack";
    int32_t retval;
    void *processptr = 0;
#ifdef _WIN32
    cmdstr = "SuperNET.exe";
    osstr = "_WIN32";
    rmstr = "del"
#else
    cmdstr = "./SuperNET";
    osstr = "__linux__";
    rmstr = "rm";
#endif
   if ( (fp= fopen(msgfname,"rb")) != 0 )
    {
        fclose(fp);
        sprintf(cmd,"%s %s",rmstr,msgfname);
        system(cmd);
    }
    if ( portable_spawn(osstr,cmdstr,myip) != 0 )
        printf("error launching (%s)\n",cmdstr);
    else
    {
        retval = set_SuperNET_url(SuperNET_url);
        if ( retval >= 0 )
        {
            processptr = portable_thread_create(poll_for_broadcasts,0);
            did_SuperNET_init = 1;
        }
        SuperNET_retval = retval;
        printf("SuperNET_retval = %d\n",SuperNET_retval);
    }
    return(processptr);
}

int32_t launch_SuperNET(char *myip)
{
    void *processptr;
    processptr = portable_thread_create(_launch_SuperNET,myip);
    return(0);
}
