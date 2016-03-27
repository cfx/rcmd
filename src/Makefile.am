AM_LDFLAGS = -pthread -lssh -lssh_threads
AM_CFLAGS = -Wall -std=c99 -O2
bin_PROGRAMS = rcmd
rcmd_SOURCES = rcmd.c

if DARWIN
AM_CFLAGS += -Qunused-arguments
endif
