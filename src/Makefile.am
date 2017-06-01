bin_PROGRAMS = rcmd
AM_CFLAGS = -Wall -std=c99 -O2
AM_LDFLAGS = -pthread
rcmd_LDADD = -lssh -lssh_threads
rcmd_SOURCES = rcmd.c

if DARWIN
AM_CFLAGS += -Qunused-arguments
endif
