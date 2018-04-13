#include "subcommand.h"
#include <fcntl.h>
#include <errno.h>

static int option_quite = 0;

extern const char *dimad_git_commit;
extern const char *dimad_build_machine;

static void
show_banner(void)
{
	info_cont("Dima daemon tool\n");
	info_cont("(C)Copyright 2018-2019, http://www.xdja.com/, Inc.\n");
	info_cont("Version: %s \n", VERSION);
	info_cont("Build Machine: %s\n", dimad_build_machine);
	info_cont("Build Time: " __DATE__ " " __TIME__ "\n\n");
}

static void
exit_notify(void)
{
	info("dima-d exiting with %d (%s)\n", errno,
		strerror(errno));
}

static void
show_version(void)
{
	info_cont("%s\n", VERSION);
}

static int
parse_options(int argc, char *argv[])
{
	char opts[] = "-Vq";
	struct option long_opts[] = {
		{ "version", no_argument, NULL, 'V' },
		{ "quite", no_argument, NULL, 'q' },
		{ 0 },	/* NULL terminated */
	};

	while (1) {
		int opt, index;

		opt = getopt_long(argc, argv, opts, long_opts, NULL);
		if (opt == -1)
			break;

		switch (opt) {
		case 'V':
			show_version();
			exit(EXIT_SUCCESS);
		case 'q':
			option_quite = 1;
			break;
		case 1:
			index = optind;
			return subcommand_parse(argv[0], optarg,
						argc - index + 1,
						argv + index - 1);
		default:
			return -1;
		}
	}

	return 0;
}

extern subcommand_t subcommand_dimad;

int
main(int argc, char *argv[], char *envp[])
{
	atexit(exit_notify);
	
	if (!option_quite)
		show_banner();

	subcommand_add(&subcommand_dimad);

	int rc = parse_options(argc, argv);
	if (rc)
		return rc;

	return subcommand_run_current();
}