# SPDX-License-Identifier: GPL-2.0

hostprogs-y	:= genksyms
always		:= $(hostprogs-y)

genksyms-objs	:= genksyms.o parse.o lex.o

# -I needed for generated C source (shipped source)
HOSTCFLAGS_parse.o := -Wno-uninitialized -I$(src)

# dependencies on generated files need to be listed explicitly
$(obj)/lex.o: $(obj)/parse.h $(obj)/keywords.c

# -I needed for generated C source (shipped source)
HOSTCFLAGS_lex.o := -I$(src)

ifdef GENERATE_PARSER

# gperf

quiet_cmd_keywords.c = GPERF   $@
      cmd_keywords.c = gperf -L ANSI-C -a -C -E -g -H is_reserved_hash	\
		       -k 1,3,$$ -N is_reserved_word -p -t $< > $@

$(obj)/keywords.c: $(obj)/keywords.gperf FORCE
	$(call if_changed,keywords.c)
	cp $@ $@_shipped

# flex

quiet_cmd_lex.c = FLEX    $@
      cmd_lex.c = flex -o$@ -d $< $(obj)/parse.h

$(obj)/lex.c: $(obj)/lex.l $(obj)/parse.h $(obj)/keywords.c FORCE
	$(call if_changed,lex.c)
	cp $@ $@_shipped

# bison

quiet_cmd_parse.c = BISON   $@
      cmd_parse.c = bison -o$@ -dtv $(filter-out FORCE,$^)

$(obj)/parse.c: $(obj)/parse.y FORCE
	$(call if_changed,parse.c)
	cp $@ $@_shipped
	cp $(@:.c=.h) $(@:.c=.h)_shipped

$(obj)/parse.h: $(obj)/parse.c ;

clean-files	+= parse.output

endif

targets += keywords.c lex.c parse.c parse.h
genksyms-objs	:= genksyms.o parse.tab.o lex.lex.o

# FIXME: fix the ambiguous grammar in parse.y and delete this hack
#
# Suppress shift/reduce, reduce/reduce conflicts warnings
# unless W=1 is specified.
#
# Just in case, run "$(YACC) --version" without suppressing stderr
# so that 'bison: not found' will be displayed if it is missing.
ifeq ($(findstring 1,$(KBUILD_ENABLE_EXTRA_GCC_CHECKS)),)

quiet_cmd_bison_no_warn = $(quiet_cmd_bison)
      cmd_bison_no_warn = $(YACC) --version >/dev/null; \
			  $(cmd_bison) 2>/dev/null

$(obj)/parse.tab.c: $(src)/parse.y FORCE
	$(call if_changed,bison_no_warn)

quiet_cmd_bison_h_no_warn = $(quiet_cmd_bison_h)
      cmd_bison_h_no_warn = $(YACC) --version >/dev/null; \
			    $(cmd_bison_h) 2>/dev/null

$(obj)/parse.tab.h: $(src)/parse.y FORCE
	$(call if_changed,bison_h_no_warn)

endif

# -I needed for generated C source (shipped source)
HOSTCFLAGS_parse.tab.o := -I$(src)
HOSTCFLAGS_lex.lex.o := -I$(src)

# dependencies on generated files need to be listed explicitly
$(obj)/lex.lex.o: $(obj)/parse.tab.h
