include version.mk
TOPDIR := $(shell pwd)
INSTALL := install
CROSS_COMPILE :=
CC := $(CROSS_COMPILE)gcc
CFLAGS := -D_GNU_SOURCE -std=gnu99 -O2 -Wall -Werror
CFLAGS += -DVERSION=\"$(VERSION)\"

TOPDIR       :=
DESTDIR     :=
DIMADIR     := /usr/sbin/xdja/dima
SERVICEDIR := /usr/lib/systemd/system

SERVICE_NAME := dima-xdja.service
BIN_NAME        := dima-d
CONF_NAME     := dima.conf

CFLAGS += -DCONF_PATH=\"$(DIMADIR)/$(CONF_NAME)\"

OBJS_$(BIN_NAME) = \
		   main.o \
		   dimad.o \
		   subcommand.o \
		   build_info.o

all: $(BIN_NAME) Makefile

clean:
	@$(RM) $(BIN_NAME) $(OBJS_$(BIN_NAME)) \
	    build_info.c

install: all
	$(INSTALL) -d -m 751 $(DESTDIR)$(DIMADIR)
	$(INSTALL) -d -m 751 $(DESTDIR)$(SERVICEDIR)
	$(INSTALL) -m 700 $(BIN_NAME) $(DESTDIR)$(DIMADIR)
	$(INSTALL) -m 600 $(CONF_NAME) $(DESTDIR)$(DIMADIR)
	$(INSTALL) -m 644 $(SERVICE_NAME) $(DESTDIR)$(SERVICEDIR)

$(BIN_NAME): $(OBJS_$(BIN_NAME)) 
	$(CC) $^ -o $@ $(CFLAGS) /usr/lib64/libimaevm.so

build_info.c: build_info.c.in
	sed  -e "s~@@DIMAD_BUILD_MACHINE@@~$(shell bash -c 'whoami | tr -d "\n"; echo -n @; uname=`uname -a`; echo -n $${uname//\~/_} | tr -d "\n"')~" \
		   -e "s~@@DIMAD_CONF_DIGEST@@~$(shell evmctl ima_hash dima.conf -n)~" \
	       < $< > $@
