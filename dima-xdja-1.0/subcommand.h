#ifndef SUBCOMMAND_H
#define SUBCOMMAND_H

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <alloca.h>
#include <getopt.h>
#include <fcntl.h>
#include <dirent.h>
#include <assert.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <termios.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <linux/limits.h>

#define dimad_assert(condition, fmt, ...)	\
do {	\
	if (!(condition)) {	\
		err(fmt ": %s\n", ##__VA_ARGS__, strerror(errno)); \
		exit(EXIT_FAILURE);	\
	}	\
} while (0)

#define __pr__(level, io, fmt, ...)	\
do {	\
	time_t __t__ = time(NULL);	\
	struct tm __loc__;	\
	localtime_r(&__t__, &__loc__);	\
	char __buf__[64]; \
	strftime(__buf__, sizeof(__buf__), "%a %b %e %T %Z %Y", &__loc__);	\
	fprintf(io, "%s: [" #level "] " fmt, __buf__, ##__VA_ARGS__);	\
} while (0)

#define die(fmt, ...)	\
do {	\
	__pr__(FAULT, stderr, fmt, ##__VA_ARGS__);	\
	exit(EXIT_FAILURE);	\
} while (0)

#ifdef DEBUG
#define dbg(fmt, ...)	\
  do {	\
	  __pr__(DEBUG, stdout, fmt, ##__VA_ARGS__);	\
  } while (0)

#define dbg_cont(fmt, ...)	\
  do {	\
	  fprintf(stdout, fmt, ##__VA_ARGS__);	\
  } while (0)
#else
#define dbg(fmt, ...)
#define dbg_cont(fmt, ...)
#endif

#define info(fmt, ...)	\
  do {	\
	  __pr__(INFO, stdout, fmt, ##__VA_ARGS__);	\
  } while (0)

#define info_cont(fmt, ...)	\
  fprintf(stdout, fmt, ##__VA_ARGS__)

#define warn(fmt, ...)	\
  do {	\
	  __pr__(WARNING, stdout, fmt, ##__VA_ARGS__);	\
  } while (0)

#define err(fmt, ...)	\
  do {	\
	  __pr__(ERROR, stderr, fmt, ##__VA_ARGS__);	\
  } while (0)

#define err_cont(fmt, ...)	\
  fprintf(stderr, fmt, ##__VA_ARGS__)

typedef struct {
	const char *name;
	const char *optstring;
	const struct option *long_opts;
	int (*parse_arg)(int opt, char *optarg);
	void (*show_usage)(char *prog);
	int (*run)(char *prog);
} subcommand_t;

extern int
subcommand_add(subcommand_t *subcmd);

extern subcommand_t *
subcommand_find(char *subcmd);

extern int
subcommand_parse(char *prog, char *subcmd, int argc, char *argv[]);

extern int
subcommand_run_current(void);

#endif	/* SUBCOMMAND_H */