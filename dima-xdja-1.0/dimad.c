#include "subcommand.h"
#include <dirent.h>
#include <sys/ioctl.h>  
#include <imaevm.h>
 
#define MAX_DIMA 30

#define READ_BUF_SIZE 256

#define DIMA_NAME_LEN 100

#define MODULE_NAME_LEN (64 - sizeof(unsigned long))

#define DIMA_SET_MEASUREMENT_MODE_CMD _IOW('d', 1, int)
#define DIMA_MEASUREMENT_PROCESS_CMD    _IOW('d', 2, int)
#define DIMA_MEASUREMENT_MODULE_CMD	   _IOW('d', 3, char[MODULE_NAME_LEN])
#define DIMA_SET_MEASUREMENT_LOCK_MODE_CMD        _IO('d', 4)
#define DIMA_SET_MEASUREMENT_UNLOCK_MODE_CMD    _IO('d', 5)

#define DIMA_MODE_PROCESS 1
#define DIMA_MODE_MODULE 2

#define CMD_ERR_OK 0
#define CMD_ERR_NOSEACH -ESRCH
#define CMD_ERR_FAILMEASURE -1

#define SUCCESS 0
#define FAILURE 1

extern const char *dimad_build_conf_digest;

extern long delete_module(const char *, unsigned int);

struct dima{
    char name[DIMA_NAME_LEN];
    int mode;
};

static int opt_sleep_time = 60;

static struct dima* opt_dimas[MAX_DIMA];
static int opt_dimas_index = 0;

static int opt_dima_measurement_mode = 0;

static int init_pipe[2];
static int do_fork = 0;
static const char *pidfile = "/var/run/dima.pid";

static char * 
strtrim(char *s) {
    char *p = s;
    char *q = s;
    while (*p==' ' || *p=='\t' || *p=='\n') ++p;
    while ((*q++=*p++));
    q -= 2;
    while (*q==' ' || *q=='\t' || *q=='\n') --q;
    *(q+1) ='\0';
    return s;
}

static void
dima_digest_dump(unsigned char *data, int len,char* out)
{
	int i;
	int nlen =0;

    out[0] = '0';
    out[1] = '1';
    nlen += 2;

	for (i = 0; i < len; i++){
		sprintf(out+nlen,"%02x", data[i]);
		nlen += 2;
	}

	out[nlen] = '\0';
}

static int
check_dima_conf(){
    unsigned char conf_hash[64];
    int conf_hashlen;
    char conf_shash[256];

    conf_hashlen = ima_calc_hash(CONF_PATH, conf_hash);
	if (conf_hashlen <= 1)
        return -1;
    
    dima_digest_dump(conf_hash,conf_hashlen,conf_shash);

    info("%s---%s\n",dimad_build_conf_digest,conf_shash);

    if(strcmp(dimad_build_conf_digest,conf_shash) == 0)
        return 0;

    return -1;
}

static int 
read_conf_value()
{
    char line[READ_BUF_SIZE];
    char name[DIMA_NAME_LEN];
    char smode[2];
    int mode;
    FILE *fp;

    if(check_dima_conf())
        return -1;

    fp = fopen(CONF_PATH,"r");
    if(fp == NULL)
        return -1;

    while (fgets(line, READ_BUF_SIZE, fp)){

        if(opt_dimas_index >= MAX_DIMA)
            break;

        sscanf(line, "%s %s", smode,name);

        char *m = strtrim(smode);
        mode = DIMA_MODE_PROCESS;
        if(strncmp(m,"M",strlen(m)) == 0)
            mode = DIMA_MODE_MODULE;

        char *p = strtrim(name);
        int len = strlen(p);
        int max_len = mode == DIMA_MODE_MODULE?MODULE_NAME_LEN:DIMA_NAME_LEN;
        if(len <= 0 || len >= max_len){
            continue ;
        }

        bool has = false;
        for(int i=0; i < opt_dimas_index; i++)
        {
            if(strcmp(opt_dimas[i]->name,p) == 0 
                &&opt_dimas[i]->mode == mode){
                has = true;
                break;
            }
        }
        if(has){
            err("Measurement name=%s already owned \n",p);
            continue ;
        }

        info("Measurement name = %s mode = %s add !!! \n",p,m);
        struct dima* a = malloc(sizeof(struct dima));
        strncpy( a->name, p, len+1);
        a->mode = mode;
        opt_dimas[opt_dimas_index++] = a;
    }

    fclose(fp);

    return 0;
}

 
static void
show_usage(char *prog)
{
    info_cont("\nUsage: %s <options> dimad <subcommand>\n", prog);
    info_cont(" The subcommand to be shown.\n");
}

static int
parse_arg(int opt, char *optarg)
{
    switch (opt) {
        case 'P':
        {
            if(opt_dimas_index >= MAX_DIMA)
                break;

            char *p = strtrim(optarg);
            int len = strlen(p);
            if(len <= 0 || len >= DIMA_NAME_LEN){
                break;
            }

            bool has = false;
            for(int i=0; i < opt_dimas_index; i++)
            {
                if(strcmp(opt_dimas[i]->name,p) == 0 
                    &&opt_dimas[i]->mode == DIMA_MODE_PROCESS){
                    has = true;
                    break;
                }
            }
            if(has) {
                err("Measurement name=%s already owned \n",p);
                break;
            }
            
            info("Measurement name = %s mode = P add !!! \n",p);
            struct dima* a = malloc(sizeof(struct dima));
            strncpy( a->name, p, len+1);
            a->mode = DIMA_MODE_PROCESS;
            opt_dimas[opt_dimas_index++] = a;
            break;
        }
         case 'M':
         {
            if(opt_dimas_index >= MAX_DIMA)
                break;

            char *p = strtrim(optarg);
            int len = strlen(p);
            if(len <= 0 || len >= MODULE_NAME_LEN){
                break;
            }

            bool has = false;
            for(int i=0; i < opt_dimas_index; i++)
            {
                if(strcmp(opt_dimas[i]->name,p) == 0 
                    &&opt_dimas[i]->mode == DIMA_MODE_MODULE){
                    has = true;
                    break;
                }
            }
            if(has) {
                err("Measurement name=%s already owned \n",p);
                break;
            }
            
            info("Measurement name = %s  mode = M add !!! \n",p);
            struct dima* a = malloc(sizeof(struct dima));
            strncpy( a->name, p, len+1);
            a->mode = DIMA_MODE_MODULE;
            opt_dimas[opt_dimas_index++] = a;
            break;
        }
        case 'O':
            opt_dima_measurement_mode = atoi(optarg);
            break;
        case 'F':
            do_fork = 1;
            break;
        case 'T':
            opt_sleep_time = atoi(optarg);
            if (opt_sleep_time <= 0){
                err("Unrecognized value\n");
                return -1;
            }
            break;
        default:
            return -1;
    }

    return 0;
}

static long* 
find_pid_by_name( char* comm)
{
    DIR *dir;
    struct dirent *next;
    long* pidList=NULL;
    int i=0;

    dir = opendir("/proc");
    if (!dir){
        err("Cannot open /proc");
        return NULL;
    }

    while ((next = readdir(dir)) != NULL) {
        FILE *status;
        char filename[READ_BUF_SIZE];
        char buffer[READ_BUF_SIZE];
        char name[READ_BUF_SIZE];

        /* Must skip ".." since that is outside /proc */
        if (strcmp(next->d_name, "..") == 0)
            continue;

        /* If it isn't a number, we don't want it */
        if (!isdigit(*next->d_name))
            continue;

        sprintf(filename, "/proc/%s/status", next->d_name);
        if (! (status = fopen(filename, "r")) ) {
            continue;
        }
        if (fgets(buffer, READ_BUF_SIZE-1, status) == NULL) {
            fclose(status);
            continue;
        }
        fclose(status);

        /* Buffer should contain a string like "Name:   binary_name" */
        sscanf(buffer, "%*s %s", name);
        if (strcmp(strtrim(name), comm) == 0) {
            //info("%s %s %s\n",buffer,strtrim(name),next->d_name);
            pidList=realloc( pidList, sizeof(long) * (i+2));
            pidList[i++]=strtol(next->d_name, NULL, 0);
        }
    }

    if (pidList) {
        pidList[i]=0;
    }
    return pidList;
}

static int 
dyn_measurement_process(int fd)
{
    int err;
    int i;
    for(i = 0;  i < opt_dimas_index; i++)
    {
        if(opt_dimas[i]->mode == DIMA_MODE_PROCESS){
            long* pids = find_pid_by_name(opt_dimas[i]->name);
            if(pids == NULL)
                continue;
    
            int n=0;
            while(pids[n] != 0){
                int pid = (int)pids[n];
                err = ioctl(fd,DIMA_MEASUREMENT_PROCESS_CMD,(unsigned long)&pid);
                info("Measurement pid=%d status=%d \n",pid,err);
                
                n++;
            }

            free(pids);
        }else if(opt_dimas[i]->mode == DIMA_MODE_MODULE){
            err = ioctl(fd,DIMA_MEASUREMENT_MODULE_CMD,(unsigned long)opt_dimas[i]->name);
            info("Measurement module name=%s status=%d \n",opt_dimas[i]->name,err);

            if(opt_dima_measurement_mode && err == CMD_ERR_FAILMEASURE){
                delete_module(opt_dimas[i]->name,O_TRUNC|O_NONBLOCK);
                info("Delete module module name=%s \n",opt_dimas[i]->name);
            }
        }
    }

    return 0;
}

static int
write_pid_file(void)
{
	int pidfd, len;
    char val[16];

    if (do_fork == 0)
        return 0;

	len = snprintf(val, sizeof(val), "%u\n", getpid());
	if (len <= 0) {
		pidfile = 0;
		return -1;
	}
	pidfd = open(pidfile, O_CREAT | O_TRUNC | O_NOFOLLOW | O_WRONLY, 0644);
	if (pidfd < 0) {
		pidfile = 0;
		return -1;
	}
	if (write(pidfd, val, (unsigned int)len) != len) {
		close(pidfd);
		pidfile = 0;
		return -1;
	}
	close(pidfd);
	return 0;
}

static int become_daemon(void)
{
	int fd, rc;
	pid_t pid;
    int status;

    if (do_fork == 0)
        return 0;

	if (pipe(init_pipe) || 
        fcntl(init_pipe[0], F_SETFD, FD_CLOEXEC) ||
        fcntl(init_pipe[0], F_SETFD, FD_CLOEXEC))
        return -1;

    pid = fork();
	switch (pid)
	{
		case 0:
			/* No longer need this...   */
			close(init_pipe[0]);

			/* Open stdin,out,err to /dev/null */
			fd = open("/dev/null", O_RDWR);
			if (fd < 0) {
				return -1;
            }

			if ((dup2(fd, 0) < 0) || (dup2(fd, 1) < 0) ||
							(dup2(fd, 2) < 0)) {
				close(fd);
				return -1;
			}
			close(fd);

			/* Change to '/' */
			rc = chdir("/");
			if (rc < 0) {
				return -1;
			}

			/* Become session/process group leader */
			setsid();
			break;
		case -1:
			return -1;
			break;
		default:
			/* Wait for the child to say its done */
			rc = read(init_pipe[0], &status, sizeof(status));
			if (rc < 0)
				return -1;

			/* Success - die a happy death */
			if (status == SUCCESS)
				_exit(0);
			else
				return -1;
			break;
	}

	return 0;
}

static 
void tell_parent(int status)
{
	int rc;

	if (do_fork == 0)
        return;

	do {
		rc = write(init_pipe[1], &status, sizeof(status));
    } while (rc < 0 && errno == EINTR);
    
    close(init_pipe[1]);
}

static int
run_dimad(char *prog)
{
    int fd;
    int err;
    int count = 0;

    if(become_daemon()){
        err("Cannot daemonize (%s) \n",strerror(errno));
        tell_parent(FAILURE);
        return -1;
    }
    write_pid_file();

    if (opt_sleep_time <= 0) {
        show_usage(prog);
        tell_parent(FAILURE);
        return -1;
    }

    read_conf_value();
    
    if(!opt_dimas_index){
        info("No process need measure.\n");
        tell_parent(FAILURE);
        return -1;
    }

    fd = open("/dev/dima",O_RDWR);
    if(fd < 0){
        err("Fail to open  /dev/dima  %s (%d)\n",strerror(errno),errno);
        tell_parent(FAILURE);
        return -1;
    }

    err = ioctl(fd,DIMA_SET_MEASUREMENT_MODE_CMD,(unsigned long)&opt_dima_measurement_mode);
    if(err){
        err("Fail to set measurement mode %s (%d)\n",strerror(errno),errno);
        close(fd);
        tell_parent(FAILURE);
        return -1;
    }

    tell_parent(SUCCESS);

    do{
        info("----------------- \n");
        info("Measurement count=%d \n",count++);

        ioctl(fd,DIMA_SET_MEASUREMENT_UNLOCK_MODE_CMD);
        err = dyn_measurement_process(fd);
        ioctl(fd,DIMA_SET_MEASUREMENT_LOCK_MODE_CMD);

        if(err) break;

        sleep(opt_sleep_time);
    }while(1);

    close(fd);

    return err;
}

static struct option long_opts[] = {
    { "process", required_argument, NULL, 'P' },
    { "module", required_argument, NULL, 'M' },
    { "measuremode", required_argument, NULL, 'O' },
    { "fork", no_argument, NULL, 'F' },
    { "time", required_argument, NULL, 'T' },
    { 0 },	/* NULL terminated */
};

subcommand_t subcommand_dimad = {
    .name = "dimad",
    .optstring = "-P:M:O:FT:",
    .long_opts = long_opts,
    .parse_arg = parse_arg,
    .show_usage = show_usage,
    .run = run_dimad,
};