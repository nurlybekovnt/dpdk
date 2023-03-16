/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Marvell.
 */

#include <errno.h>
#include <getopt.h>

#include <rte_memory.h>
#include <rte_mldev.h>
#include <rte_string_fns.h>

#include "ml_common.h"
#include "ml_test.h"
#include "parser.h"

typedef int (*option_parser_t)(struct ml_options *opt, const char *arg);

void
ml_options_default(struct ml_options *opt)
{
	memset(opt, 0, sizeof(*opt));
	strlcpy(opt->test_name, "device_ops", ML_TEST_NAME_MAX_LEN);
	opt->dev_id = 0;
	opt->socket_id = SOCKET_ID_ANY;
	opt->nb_filelist = 0;
	opt->debug = false;
}

struct long_opt_parser {
	const char *lgopt_name;
	option_parser_t parser_fn;
};

static int
ml_parse_test_name(struct ml_options *opt, const char *arg)
{
	strlcpy(opt->test_name, arg, ML_TEST_NAME_MAX_LEN);
	return 0;
}

static int
ml_parse_dev_id(struct ml_options *opt, const char *arg)
{
	int ret;

	ret = parser_read_int16(&opt->dev_id, arg);

	if (ret < 0)
		return -EINVAL;

	return ret;
}

static int
ml_parse_socket_id(struct ml_options *opt, const char *arg)
{
	opt->socket_id = atoi(arg);

	return 0;
}

static int
ml_parse_models(struct ml_options *opt, const char *arg)
{
	const char *delim = ",";
	char models[PATH_MAX];
	char *token;
	int ret = 0;

	strlcpy(models, arg, PATH_MAX);

	token = strtok(models, delim);
	while (token != NULL) {
		strlcpy(opt->filelist[opt->nb_filelist].model, token, PATH_MAX);
		opt->nb_filelist++;

		if (opt->nb_filelist >= ML_TEST_MAX_MODELS) {
			ml_err("Exceeded model count, max = %d\n", ML_TEST_MAX_MODELS);
			ret = -EINVAL;
			break;
		}
		token = strtok(NULL, delim);
	}

	if (opt->nb_filelist == 0) {
		ml_err("Models list is empty. Need at least one model for the test");
		ret = -EINVAL;
	}

	return ret;
}

static void
ml_dump_test_options(const char *testname)
{
	if (strcmp(testname, "device_ops") == 0)
		printf("\n");

	if (strcmp(testname, "model_ops") == 0) {
		printf("\t\t--models           : comma separated list of models\n");
		printf("\n");
	}
}

static void
print_usage(char *program)
{
	printf("\nusage : %s [EAL options] -- [application options]\n", program);
	printf("application options:\n");
	printf("\t--test             : name of the test application to run\n"
	       "\t--dev_id           : device id of the ML device\n"
	       "\t--socket_id        : socket_id of application resources\n"
	       "\t--debug            : enable debug mode\n"
	       "\t--help             : print help\n");
	printf("\n");
	printf("available tests and test specific application options:\n");
	ml_test_dump_names(ml_dump_test_options);
}

static struct option lgopts[] = {
	{ML_TEST, 1, 0, 0},
	{ML_DEVICE_ID, 1, 0, 0},
	{ML_SOCKET_ID, 1, 0, 0},
	{ML_MODELS, 1, 0, 0},
	{ML_DEBUG, 0, 0, 0},
	{ML_HELP, 0, 0, 0},
	{NULL, 0, 0, 0}};

static int
ml_opts_parse_long(int opt_idx, struct ml_options *opt)
{
	unsigned int i;

	struct long_opt_parser parsermap[] = {
		{ML_TEST, ml_parse_test_name},
		{ML_DEVICE_ID, ml_parse_dev_id},
		{ML_SOCKET_ID, ml_parse_socket_id},
		{ML_MODELS, ml_parse_models},
	};

	for (i = 0; i < RTE_DIM(parsermap); i++) {
		if (strncmp(lgopts[opt_idx].name, parsermap[i].lgopt_name,
			    strlen(lgopts[opt_idx].name)) == 0)
			return parsermap[i].parser_fn(opt, optarg);
	}

	return -EINVAL;
}

int
ml_options_parse(struct ml_options *opt, int argc, char **argv)
{
	int opt_idx;
	int retval;
	int opts;

	while ((opts = getopt_long(argc, argv, "", lgopts, &opt_idx)) != EOF) {
		switch (opts) {
		case 0: /* parse long options */
			if (!strcmp(lgopts[opt_idx].name, "debug")) {
				opt->debug = true;
				break;
			}

			if (!strcmp(lgopts[opt_idx].name, "help")) {
				print_usage(argv[0]);
				exit(EXIT_SUCCESS);
			}

			retval = ml_opts_parse_long(opt_idx, opt);
			if (retval != 0)
				return retval;
			break;
		default:
			return -EINVAL;
		}
	}

	return 0;
}

void
ml_options_dump(struct ml_options *opt)
{
	struct rte_ml_dev_info dev_info;

	rte_ml_dev_info_get(opt->dev_id, &dev_info);

	ml_dump("driver", "%s", dev_info.driver_name);
	ml_dump("test", "%s", opt->test_name);
	ml_dump("dev_id", "%d", opt->dev_id);

	if (opt->socket_id == SOCKET_ID_ANY)
		ml_dump("socket_id", "%d (SOCKET_ID_ANY)", opt->socket_id);
	else
		ml_dump("socket_id", "%d", opt->socket_id);

	ml_dump("debug", "%s", (opt->debug ? "true" : "false"));
}
