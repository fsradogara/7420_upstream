/*
 * Copyright (C) 2002 Roman Zippel <zippel@linux-m68k.org>
 * Released under the terms of the GNU GPL v2.0.
 */

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#define LKC_DIRECT_LINK
#include <getopt.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <errno.h>

#include "lkc.h"

static void conf(struct menu *menu);
static void check_conf(struct menu *menu);

enum {
	ask_all,
	ask_new,
	ask_silent,
	set_default,
	set_yes,
	set_mod,
	set_no,
	set_random
} input_mode = ask_all;
char *defconfig_file;

static int indent = 1;
static void xfgets(char *str, int size, FILE *in);

enum input_mode {
	oldaskconfig,
	syncconfig,
	oldconfig,
	allnoconfig,
	allyesconfig,
	allmodconfig,
	alldefconfig,
	randconfig,
	defconfig,
	savedefconfig,
	listnewconfig,
	olddefconfig,
};
static enum input_mode input_mode = oldaskconfig;

static int indent = 1;
static int tty_stdio;
static int sync_kconfig;
static int conf_cnt;
static char line[PATH_MAX];
static struct menu *rootEntry;

static char nohelp_text[] = N_("Sorry, no help available for this option yet.\n");

static const char *get_help(struct menu *menu)
{
	if (menu_has_help(menu))
		return _(menu_get_help(menu));
	else
		return nohelp_text;
static void print_help(struct menu *menu)
{
	struct gstr help = str_new();

	menu_get_ext_help(menu, &help);

	printf("\n%s\n", str_get(&help));
	str_free(&help);
}

static void strip(char *str)
{
	char *p = str;
	int l;

	while ((isspace(*p)))
		p++;
	l = strlen(p);
	if (p != str)
		memmove(str, p, l + 1);
	if (!l)
		return;
	p = str + l - 1;
	while ((isspace(*p)))
		*p-- = 0;
}

/* Helper function to facilitate fgets() by Jean Sacren. */
static void xfgets(char *str, int size, FILE *in)
{
	if (!fgets(str, size, in))
		fprintf(stderr, "\nError in reading or end of file.\n");

	if (!tty_stdio)
		printf("%s", str);
}

static int conf_askvalue(struct symbol *sym, const char *def)
{
	enum symbol_type type = sym_get_type(sym);

	if (!sym_has_value(sym))
		printf("(NEW) ");

	line[0] = '\n';
	line[1] = 0;

	if (!sym_is_changable(sym)) {
		printf("%s\n", def);
		line[0] = '\n';
		line[1] = 0;
		return 0;
	}

	switch (input_mode) {
	case ask_new:
	case ask_silent:
	case oldconfig:
	case syncconfig:
		if (sym_has_value(sym)) {
			printf("%s\n", def);
			return 0;
		}
		check_stdin();
	case ask_all:
		fflush(stdout);
		fgets(line, 128, stdin);
		/* fall through */
	case oldaskconfig:
		fflush(stdout);
		xfgets(line, sizeof(line), stdin);
		return 1;
	default:
		break;
	}

	switch (type) {
	case S_INT:
	case S_HEX:
	case S_STRING:
		printf("%s\n", def);
		return 1;
	default:
		;
	}
	printf("%s", line);
	return 1;
}

int conf_string(struct menu *menu)
static int conf_string(struct menu *menu)
{
	struct symbol *sym = menu->sym;
	const char *def;

	while (1) {
		printf("%*s%s ", indent - 1, "", menu->prompt->text);
		printf("(%s) ", sym->name);
		def = sym_get_string_value(sym);
		if (sym_get_string_value(sym))
			printf("[%s] ", def);
		if (!conf_askvalue(sym, def))
			return 0;
		switch (line[0]) {
		case '\n':
			break;
		case '?':
			/* print help */
			if (line[1] == '\n') {
				printf("\n%s\n", get_help(menu));
				def = NULL;
				break;
			}
				print_help(menu);
				def = NULL;
				break;
			}
			/* fall through */
		default:
			line[strlen(line)-1] = 0;
			def = line;
		}
		if (def && sym_set_string_value(sym, def))
			return 0;
	}
}

static int conf_sym(struct menu *menu)
{
	struct symbol *sym = menu->sym;
	int type;
	tristate oldval, newval;

	while (1) {
		printf("%*s%s ", indent - 1, "", menu->prompt->text);
		if (sym->name)
			printf("(%s) ", sym->name);
		type = sym_get_type(sym);
		putchar('[');
		oldval = sym_get_tristate_value(sym);
		switch (oldval) {
		case no:
			putchar('N');
			break;
		case mod:
			putchar('M');
			break;
		case yes:
			putchar('Y');
			break;
		}
		if (oldval != no && sym_tristate_within_range(sym, no))
			printf("/n");
		if (oldval != mod && sym_tristate_within_range(sym, mod))
			printf("/m");
		if (oldval != yes && sym_tristate_within_range(sym, yes))
			printf("/y");
		printf("/?] ");
		if (!conf_askvalue(sym, sym_get_string_value(sym)))
			return 0;
		strip(line);

		switch (line[0]) {
		case 'n':
		case 'N':
			newval = no;
			if (!line[1] || !strcmp(&line[1], "o"))
				break;
			continue;
		case 'm':
		case 'M':
			newval = mod;
			if (!line[1])
				break;
			continue;
		case 'y':
		case 'Y':
			newval = yes;
			if (!line[1] || !strcmp(&line[1], "es"))
				break;
			continue;
		case 0:
			newval = oldval;
			break;
		case '?':
			goto help;
		default:
			continue;
		}
		if (sym_set_tristate_value(sym, newval))
			return 0;
help:
		printf("\n%s\n", get_help(menu));
		print_help(menu);
	}
}

static int conf_choice(struct menu *menu)
{
	struct symbol *sym, *def_sym;
	struct menu *child;
	int type;
	bool is_new;

	sym = menu->sym;
	type = sym_get_type(sym);
	bool is_new;

	sym = menu->sym;
	is_new = !sym_has_value(sym);
	if (sym_is_changable(sym)) {
		conf_sym(menu);
		sym_calc_value(sym);
		switch (sym_get_tristate_value(sym)) {
		case no:
			return 1;
		case mod:
			return 0;
		case yes:
			break;
		}
	} else {
		switch (sym_get_tristate_value(sym)) {
		case no:
			return 1;
		case mod:
			printf("%*s%s\n", indent - 1, "", menu_get_prompt(menu));
			return 0;
		case yes:
			break;
		}
	}

	while (1) {
		int cnt, def;

		printf("%*s%s\n", indent - 1, "", menu_get_prompt(menu));
		def_sym = sym_get_choice_value(sym);
		cnt = def = 0;
		line[0] = 0;
		for (child = menu->list; child; child = child->next) {
			if (!menu_is_visible(child))
				continue;
			if (!child->sym) {
				printf("%*c %s\n", indent, '*', menu_get_prompt(child));
				continue;
			}
			cnt++;
			if (child->sym == def_sym) {
				def = cnt;
				printf("%*c", indent, '>');
			} else
				printf("%*c", indent, ' ');
			printf(" %d. %s", cnt, menu_get_prompt(child));
			if (child->sym->name)
				printf(" (%s)", child->sym->name);
			if (!sym_has_value(child->sym))
				printf(" (NEW)");
			printf("\n");
		}
		printf("%*schoice", indent - 1, "");
		if (cnt == 1) {
			printf("[1]: 1\n");
			goto conf_childs;
		}
		printf("[1-%d?]: ", cnt);
		switch (input_mode) {
		case ask_new:
		case ask_silent:
		case oldconfig:
		case syncconfig:
			if (!is_new) {
				cnt = def;
				printf("%d\n", cnt);
				break;
			}
			check_stdin();
		case ask_all:
			fflush(stdout);
			fgets(line, 128, stdin);
			strip(line);
			if (line[0] == '?') {
				printf("\n%s\n", get_help(menu));
			/* fall through */
		case oldaskconfig:
			fflush(stdout);
			xfgets(line, sizeof(line), stdin);
			strip(line);
			if (line[0] == '?') {
				print_help(menu);
				continue;
			}
			if (!line[0])
				cnt = def;
			else if (isdigit(line[0]))
				cnt = atoi(line);
			else
				continue;
			break;
		default:
			break;
		}

	conf_childs:
		for (child = menu->list; child; child = child->next) {
			if (!child->sym || !menu_is_visible(child))
				continue;
			if (!--cnt)
				break;
		}
		if (!child)
			continue;
		if (line[strlen(line) - 1] == '?') {
			printf("\n%s\n", get_help(child));
		if (line[0] && line[strlen(line) - 1] == '?') {
			print_help(child);
			continue;
		}
		sym_set_choice_value(sym, child->sym);
		for (child = child->list; child; child = child->next) {
			indent += 2;
			conf(child);
			indent -= 2;
		}
		return 1;
	}
}

static void conf(struct menu *menu)
{
	struct symbol *sym;
	struct property *prop;
	struct menu *child;

	if (!menu_is_visible(menu))
		return;

	sym = menu->sym;
	prop = menu->prompt;
	if (prop) {
		const char *prompt;

		switch (prop->type) {
		case P_MENU:
			if (input_mode == ask_silent && rootEntry != menu) {
				check_conf(menu);
				return;
			}
			if ((input_mode == silentoldconfig ||
			     input_mode == listnewconfig ||
			     input_mode == olddefconfig) &&
			    rootEntry != menu) {
			/*
			 * Except in oldaskconfig mode, we show only menus that
			 * contain new symbols.
			 */
			if (input_mode != oldaskconfig && rootEntry != menu) {
				check_conf(menu);
				return;
			}
			/* fall through */
		case P_COMMENT:
			prompt = menu_get_prompt(menu);
			if (prompt)
				printf("%*c\n%*c %s\n%*c\n",
					indent, '*',
					indent, '*', prompt,
					indent, '*');
		default:
			;
		}
	}

	if (!sym)
		goto conf_childs;

	if (sym_is_choice(sym)) {
		conf_choice(menu);
		if (sym->curr.tri != mod)
			return;
		goto conf_childs;
	}

	switch (sym->type) {
	case S_INT:
	case S_HEX:
	case S_STRING:
		conf_string(menu);
		break;
	default:
		conf_sym(menu);
		break;
	}

conf_childs:
	if (sym)
		indent += 2;
	for (child = menu->list; child; child = child->next)
		conf(child);
	if (sym)
		indent -= 2;
}

static void check_conf(struct menu *menu)
{
	struct symbol *sym;
	struct menu *child;

	if (!menu_is_visible(menu))
		return;

	sym = menu->sym;
	if (sym && !sym_has_value(sym)) {
		if (sym_is_changable(sym) ||
		    (sym_is_choice(sym) && sym_get_tristate_value(sym) == yes)) {
			if (!conf_cnt++)
				printf(_("*\n* Restart config...\n*\n"));
			rootEntry = menu_get_parent_menu(menu);
			conf(rootEntry);
			if (input_mode == listnewconfig) {
				if (sym->name) {
					const char *str;

					if (sym->type == S_STRING) {
						str = sym_get_string_value(sym);
						str = sym_escape_string_value(str);
						printf("%s%s=%s\n", CONFIG_, sym->name, str);
						free((void *)str);
					} else {
						str = sym_get_string_value(sym);
						printf("%s%s=%s\n", CONFIG_, sym->name, str);
					}
				}
			} else {
				if (!conf_cnt++)
					printf("*\n* Restart config...\n*\n");
				rootEntry = menu_get_parent_menu(menu);
				conf(rootEntry);
			}
		}
	}

	for (child = menu->list; child; child = child->next)
		check_conf(child);
}

int main(int ac, char **av)
{
	int opt;
	const char *name;
static struct option long_opts[] = {
	{"oldaskconfig",    no_argument,       NULL, oldaskconfig},
	{"oldconfig",       no_argument,       NULL, oldconfig},
	{"syncconfig",      no_argument,       NULL, syncconfig},
	{"defconfig",       optional_argument, NULL, defconfig},
	{"savedefconfig",   required_argument, NULL, savedefconfig},
	{"allnoconfig",     no_argument,       NULL, allnoconfig},
	{"allyesconfig",    no_argument,       NULL, allyesconfig},
	{"allmodconfig",    no_argument,       NULL, allmodconfig},
	{"alldefconfig",    no_argument,       NULL, alldefconfig},
	{"randconfig",      no_argument,       NULL, randconfig},
	{"listnewconfig",   no_argument,       NULL, listnewconfig},
	{"olddefconfig",    no_argument,       NULL, olddefconfig},
	/*
	 * oldnoconfig is an alias of olddefconfig, because people already
	 * are dependent on its behavior(sets new symbols to their default
	 * value but not 'n') with the counter-intuitive name.
	 */
	{"oldnoconfig",     no_argument,       NULL, olddefconfig},
	{NULL, 0, NULL, 0}
};

static void conf_usage(const char *progname)
{

	printf("Usage: %s [-s] [option] <kconfig-file>\n", progname);
	printf("[option] is _one_ of the following:\n");
	printf("  --listnewconfig         List new options\n");
	printf("  --oldaskconfig          Start a new configuration using a line-oriented program\n");
	printf("  --oldconfig             Update a configuration using a provided .config as base\n");
	printf("  --syncconfig            Similar to oldconfig but generates configuration in\n"
	       "                          include/{generated/,config/}\n");
	printf("  --olddefconfig          Same as oldconfig but sets new symbols to their default value\n");
	printf("  --oldnoconfig           An alias of olddefconfig\n");
	printf("  --defconfig <file>      New config with default defined in <file>\n");
	printf("  --savedefconfig <file>  Save the minimal current configuration to <file>\n");
	printf("  --allnoconfig           New config where all options are answered with no\n");
	printf("  --allyesconfig          New config where all options are answered with yes\n");
	printf("  --allmodconfig          New config where all options are answered with mod\n");
	printf("  --alldefconfig          New config with all symbols set to default\n");
	printf("  --randconfig            New config with random answer to all options\n");
}

int main(int ac, char **av)
{
	const char *progname = av[0];
	int opt;
	const char *name, *defconfig_file = NULL /* gcc uninit */;
	struct stat tmpstat;
	int no_conf_write = 0;

	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);

	while ((opt = getopt(ac, av, "osdD:nmyrh")) != -1) {
		switch (opt) {
		case 'o':
			input_mode = ask_silent;
			break;
		case 's':
			input_mode = ask_silent;
			sync_kconfig = 1;
			break;
		case 'd':
			input_mode = set_default;
			break;
		case 'D':
			input_mode = set_default;
			defconfig_file = optarg;
			break;
		case 'n':
			input_mode = set_no;
			break;
		case 'm':
			input_mode = set_mod;
			break;
		case 'y':
			input_mode = set_yes;
			break;
		case 'r':
			input_mode = set_random;
			srand(time(NULL));
			break;
		case 'h':
			printf(_("See README for usage info\n"));
			exit(0);
			break;
		default:
			fprintf(stderr, _("See README for usage info\n"));
			exit(1);
	tty_stdio = isatty(0) && isatty(1) && isatty(2);
	tty_stdio = isatty(0) && isatty(1);

	while ((opt = getopt_long(ac, av, "s", long_opts, NULL)) != -1) {
		if (opt == 's') {
			conf_set_message_callback(NULL);
			continue;
		}
		input_mode = (enum input_mode)opt;
		switch (opt) {
		case syncconfig:
			/*
			 * syncconfig is invoked during the build stage.
			 * Suppress distracting "configuration written to ..."
			 */
			conf_set_message_callback(NULL);
			sync_kconfig = 1;
			break;
		case defconfig:
		case savedefconfig:
			defconfig_file = optarg;
			break;
		case randconfig:
		{
			struct timeval now;
			unsigned int seed;
			char *seed_env;

			/*
			 * Use microseconds derived seed,
			 * compensate for systems where it may be zero
			 */
			gettimeofday(&now, NULL);
			seed = (unsigned int)((now.tv_sec + 1) * (now.tv_usec + 1));

			seed_env = getenv("KCONFIG_SEED");
			if( seed_env && *seed_env ) {
				char *endp;
				int tmp = (int)strtol(seed_env, &endp, 0);
				if (*endp == '\0') {
					seed = tmp;
				}
			}
			fprintf( stderr, "KCONFIG_SEED=0x%X\n", seed );
			srand(seed);
			break;
		}
		case oldaskconfig:
		case oldconfig:
		case allnoconfig:
		case allyesconfig:
		case allmodconfig:
		case alldefconfig:
		case listnewconfig:
		case olddefconfig:
			break;
		case '?':
			conf_usage(progname);
			exit(1);
			break;
		}
	}
	if (ac == optind) {
		fprintf(stderr, "%s: Kconfig file missing\n", av[0]);
		conf_usage(progname);
		exit(1);
	}
	name = av[optind];
	conf_parse(name);
	//zconfdump(stdout);
	if (sync_kconfig) {
		if (stat(".config", &tmpstat)) {
			fprintf(stderr, _("***\n"
				"*** You have not yet configured your kernel!\n"
				"*** (missing kernel .config file)\n"
				"***\n"
				"*** Please run some configurator (e.g. \"make oldconfig\" or\n"
				"*** \"make menuconfig\" or \"make xconfig\").\n"
				"***\n"));
		name = conf_get_configname();
		if (stat(name, &tmpstat)) {
			fprintf(stderr, "***\n"
				"*** Configuration file \"%s\" not found!\n"
				"***\n"
				"*** Please run some configurator (e.g. \"make oldconfig\" or\n"
				"*** \"make menuconfig\" or \"make xconfig\").\n"
				"***\n", name);
			exit(1);
		}
	}

	switch (input_mode) {
	case set_default:
	case defconfig:
		if (!defconfig_file)
			defconfig_file = conf_get_default_confname();
		if (conf_read(defconfig_file)) {
			fprintf(stderr,
				"***\n"
				  "*** Can't find default configuration \"%s\"!\n"
				  "***\n",
				defconfig_file);
			exit(1);
		}
		break;
	case ask_silent:
	case ask_all:
	case ask_new:
		conf_read(NULL);
		break;
	case set_no:
	case set_mod:
	case set_yes:
	case set_random:
		name = getenv("KCONFIG_ALLCONFIG");
		if (name && !stat(name, &tmpstat)) {
			conf_read_simple(name, S_DEF_USER);
			break;
		}
		switch (input_mode) {
		case set_no:	 name = "allno.config"; break;
		case set_mod:	 name = "allmod.config"; break;
		case set_yes:	 name = "allyes.config"; break;
		case set_random: name = "allrandom.config"; break;
		default: break;
		}
		if (!stat(name, &tmpstat))
			conf_read_simple(name, S_DEF_USER);
		else if (!stat("all.config", &tmpstat))
			conf_read_simple("all.config", S_DEF_USER);
	case savedefconfig:
	case syncconfig:
	case oldaskconfig:
	case oldconfig:
	case listnewconfig:
	case olddefconfig:
		conf_read(NULL);
		break;
	case allnoconfig:
	case allyesconfig:
	case allmodconfig:
	case alldefconfig:
	case randconfig:
		name = getenv("KCONFIG_ALLCONFIG");
		if (!name)
			break;
		if ((strcmp(name, "") != 0) && (strcmp(name, "1") != 0)) {
			if (conf_read_simple(name, S_DEF_USER)) {
				fprintf(stderr,
					"*** Can't read seed configuration \"%s\"!\n",
					name);
				exit(1);
			}
			break;
		}
		switch (input_mode) {
		case allnoconfig:	name = "allno.config"; break;
		case allyesconfig:	name = "allyes.config"; break;
		case allmodconfig:	name = "allmod.config"; break;
		case alldefconfig:	name = "alldef.config"; break;
		case randconfig:	name = "allrandom.config"; break;
		default: break;
		}
		if (conf_read_simple(name, S_DEF_USER) &&
		    conf_read_simple("all.config", S_DEF_USER)) {
			fprintf(stderr,
				"*** KCONFIG_ALLCONFIG set, but no \"%s\" or \"all.config\" file found\n",
				name);
			exit(1);
		}
		break;
	default:
		break;
	}

	if (sync_kconfig) {
		name = getenv("KCONFIG_NOSILENTUPDATE");
		if (name && *name) {
			if (conf_get_changed()) {
				fprintf(stderr,
					_("\n*** Kernel configuration requires explicit update.\n\n"));
				return 1;
			}
		}
		valid_stdin = isatty(0) && isatty(1) && isatty(2);
	}

	switch (input_mode) {
	case set_no:
		conf_set_all_new_symbols(def_no);
		break;
	case set_yes:
		conf_set_all_new_symbols(def_yes);
		break;
	case set_mod:
		conf_set_all_new_symbols(def_mod);
		break;
	case set_random:
		conf_set_all_new_symbols(def_random);
		break;
	case set_default:
		conf_set_all_new_symbols(def_default);
		break;
	case ask_new:
	case ask_all:
		rootEntry = &rootmenu;
		conf(&rootmenu);
		input_mode = ask_silent;
		/* fall through */
	case ask_silent:
					_("\n*** The configuration requires explicit update.\n\n"));
					"\n*** The configuration requires explicit update.\n\n");
				return 1;
			}
			no_conf_write = 1;
		}
	}

	switch (input_mode) {
	case allnoconfig:
		conf_set_all_new_symbols(def_no);
		break;
	case allyesconfig:
		conf_set_all_new_symbols(def_yes);
		break;
	case allmodconfig:
		conf_set_all_new_symbols(def_mod);
		break;
	case alldefconfig:
		conf_set_all_new_symbols(def_default);
		break;
	case randconfig:
		/* Really nothing to do in this loop */
		while (conf_set_all_new_symbols(def_random)) ;
		break;
	case defconfig:
		conf_set_all_new_symbols(def_default);
		break;
	case savedefconfig:
		break;
	case oldaskconfig:
		rootEntry = &rootmenu;
		conf(&rootmenu);
		input_mode = oldconfig;
		/* fall through */
	case oldconfig:
	case listnewconfig:
	case syncconfig:
		/* Update until a loop caused no more changes */
		do {
			conf_cnt = 0;
			check_conf(&rootmenu);
		} while (conf_cnt);
		} while (conf_cnt &&
			 (input_mode != listnewconfig &&
			  input_mode != olddefconfig));
		break;
	}

	if (sync_kconfig) {
		/* silentoldconfig is used during the build so we shall update autoconf.
		 * All other commands are only used to generate a config.
		 */
		if (conf_get_changed() && conf_write(NULL)) {
			fprintf(stderr, _("\n*** Error during writing of the kernel configuration.\n\n"));
			exit(1);
		}
		if (conf_write_autoconf()) {
			fprintf(stderr, _("\n*** Error during update of the kernel configuration.\n\n"));
			return 1;
		}
	} else {
		if (conf_write(NULL)) {
			fprintf(stderr, _("\n*** Error during writing of the kernel configuration.\n\n"));
			fprintf(stderr, _("\n*** Error during writing of the configuration.\n\n"));
			exit(1);
		}
		if (conf_write_autoconf()) {
			fprintf(stderr, _("\n*** Error during update of the configuration.\n\n"));
			return 1;
		}
	} else if (input_mode == savedefconfig) {
		break;
	case olddefconfig:
	default:
		break;
	}

	if (input_mode == savedefconfig) {
		if (conf_write_defconfig(defconfig_file)) {
			fprintf(stderr, "n*** Error while saving defconfig to: %s\n\n",
				defconfig_file);
			return 1;
		}
	} else if (input_mode != listnewconfig) {
		if (!no_conf_write && conf_write(NULL)) {
			fprintf(stderr, "\n*** Error during writing of the configuration.\n\n");
			exit(1);
		}

		/*
		 * Create auto.conf if it does not exist.
		 * This prevents GNU Make 4.1 or older from emitting
		 * "include/config/auto.conf: No such file or directory"
		 * in the top-level Makefile
		 *
		 * syncconfig always creates or updates auto.conf because it is
		 * used during the build.
		 */
		if (conf_write_autoconf(sync_kconfig) && sync_kconfig) {
			fprintf(stderr,
				"\n*** Error during sync of the configuration.\n\n");
			return 1;
		}
	}
	return 0;
}
