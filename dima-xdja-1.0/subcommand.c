#include "subcommand.h"

#define MAX_SUBCOMMANDS			16

static subcommand_t *curr_subcommand;
static unsigned int nr_subcommand;
static subcommand_t *subcommands[MAX_SUBCOMMANDS];
static char *prog_name;

int
subcommand_add(subcommand_t *subcmd)
{
	if (!subcmd->name || !subcmd->optstring || !subcmd->long_opts
			|| !subcmd->parse_arg)
		return -1;

	if (nr_subcommand >= MAX_SUBCOMMANDS)
		return -1;

	subcommands[nr_subcommand++] = subcmd;

	return 0;
}

subcommand_t *
subcommand_find(char *subcmd)
{
	unsigned int i;

	for (i = 0; i < nr_subcommand; ++i) {
		if (!strcmp(subcmd, subcommands[i]->name))
			break;
	}
	if (i == nr_subcommand)
		return NULL;

	return subcommands[i];
}

int
subcommand_parse(char *prog, char *subcmd, int argc, char *argv[])
{
	subcommand_t *cmd;

	cmd = subcommand_find(subcmd);
	if (!cmd) {
		return -1;
	}

	optind = 1;
	opterr = 0;

	while (1) {
		int opt;

		opt = getopt_long(argc, argv, cmd->optstring,
				  cmd->long_opts, NULL);
		if (opt == -1)
			break;

		switch (opt) {
		default:
			if (cmd->parse_arg(opt, optarg))
				return -1;
			break;
		case '?':
		case ':':
			cmd->show_usage(prog);
			return -1;
		}
	}

	curr_subcommand = cmd;
	prog_name = prog;

	return 0;
}

int
subcommand_run_current(void)
{
	if (!curr_subcommand)
		return -1;

	return curr_subcommand->run(prog_name);
}
